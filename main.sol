// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Bloom
/// @notice Compound-style yield vault with tiered lock buckets and harvest batching. Deploy and forget; all roles set at construction.
/// @dev Keeper allocates yield, operator can pause; treasury receives protocol share. Chests are lock-period buckets; seeds are deposits.
/// Remix: open in remix.ethereum.org; compiler 0.8.20+; deploy with no args.
///
/// ## Roles
/// - keeper: allocates harvested yield to chests, updates strategy weights
/// - operator: pause/unpause, set fee parameters within caps
/// - treasury: receives protocol fee share (immutable)
///
/// ## Chests
/// Each user has chests per lock tier. Deposits (seeds) lock until unlockBlock; yield accrues via harvest and is distributed by tier.
/// ## Harvest
/// Keeper calls harvest() with new yield; it is split by BASIS and distributed to active chests by weight.
///
/// ## Integration notes
/// Frontends should call getTier() for each tier index to show lock duration and weight.
/// After harvest(), keeper must call allocateHarvest() to push yield into tier accrue-per-seed.
/// User flows: openChest(tier) -> seed(chestId) with ETH; after unlockBlock, withdraw(chestId).
///
/// ## Security
/// ReentrancyGuard on all state-changing external functions; Pausable for operator.
/// Treasury address is immutable. No upgrade path; deploy new contract to migrate.
///
/// ## Gas
/// Batch operations (openChestBatch, seedBatch, withdrawBatch) save gas when managing multiple chests.

import "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/v4.9.6/contracts/security/ReentrancyGuard.sol";
import "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/v4.9.6/contracts/security/Pausable.sol";

contract Bloom is ReentrancyGuard, Pausable {

    // -------------------------------------------------------------------------
    // EVENTS
    // -------------------------------------------------------------------------

    event ChestOpened(
        address indexed owner,
        uint8 indexed tierIndex,
        uint256 chestId,
        uint256 unlockBlock,
        uint256 atBlock
    );
    event SeedDeposited(
        address indexed owner,
        uint256 indexed chestId,
        uint256 amountWei,
        uint256 newSeedBalance,
        uint256 atBlock
    );
    event YieldHarvested(
        uint256 totalYieldWei,
        uint256 treasuryShareWei,
        uint256 distributedWei,
        uint256 atBlock
    );
    event ChestWithdrawn(
        address indexed owner,
        uint256 indexed chestId,
        uint256 seedAmount,
        uint256 yieldAmount,
        uint256 atBlock
    );
    event YieldAllocatedToTier(uint8 indexed tierIndex, uint256 amountWei, uint256 atBlock);
    event KeeperUpdated(address indexed previousKeeper, address indexed newKeeper);
    event OperatorUpdated(address indexed previousOperator, address indexed newOperator);
    event ProtocolFeeBasisSet(uint256 previousBasis, uint256 newBasis, uint256 atBlock);
    event GardenPaused(address indexed by, uint256 atBlock);
    event GardenUnpaused(address indexed by, uint256 atBlock);
    event TreasuryWithdrawn(address indexed to, uint256 amountWei, uint256 atBlock);
    event EmergencySweep(address indexed token, address indexed to, uint256 amountWei);
    event TierWeightUpdated(uint8 indexed tierIndex, uint256 previousWeight, uint256 newWeight, uint256 atBlock);
    event ChestOpenedBatch(address indexed owner, uint256[] chestIds, uint8[] tierIndices, uint256 atBlock);
    event SeedDepositedBatch(address indexed owner, uint256[] chestIds, uint256 totalAmountWei, uint256 atBlock);
    event ChestWithdrawnBatch(address indexed owner, uint256[] chestIds, uint256 totalSeedWei, uint256 totalYieldWei, uint256 atBlock);

    // -------------------------------------------------------------------------
    // ERRORS
    // -------------------------------------------------------------------------

    error BLM_ZeroDeposit();
    error BLM_ZeroAddress();
    error BLM_NotKeeper();
    error BLM_NotOperator();
    error BLM_TransferFailed();
    error BLM_ChestLocked();
    error BLM_ChestNotFound();
    error BLM_NotChestOwner();
    error BLM_InvalidTier();
    error BLM_HarvestZero();
    error BLM_Paused();
    error BLM_FeeBasisTooHigh();
    error BLM_WithdrawZero();
    error BLM_NoTreasuryShare();
    error BLM_ArrayLengthMismatch();
    error BLM_MaxChestsPerUser();
    error BLM_MinLockBlocks();
    error BLM_DuplicateChest();
    error BLM_BatchTooLarge();
    error BLM_InvalidWeight();
    error BLM_TotalMismatch();

    // -------------------------------------------------------------------------
    // CONSTANTS
    // -------------------------------------------------------------------------

    uint256 public constant BLOOM_BASIS_DENOM = 10_000;
    uint256 public constant BLOOM_MAX_FEE_BASIS = 500; // 5% cap
    uint256 public constant BLOOM_MAX_TIERS = 8;
    uint256 public constant BLOOM_MAX_CHESTS_PER_USER = 32;
    uint256 public constant BLOOM_MIN_LOCK_BLOCKS = 64;
    uint256 public constant BLOOM_MAX_LOCK_BLOCKS = 2_097_152; // ~1 year at 15s
    uint256 public constant BLOOM_BATCH_SIZE = 16;
    uint256 public constant BLOOM_SCALE = 1e18;
    uint256 public constant BLOOM_MAX_WEIGHT = 10_000;
    bytes32 public constant BLOOM_DOMAIN_SALT =
        bytes32(uint256(0x3d7f1a9e5c2b4e6f8a0c2e4f6a8b0d2e4f6a8b0c2e4f6a8b0d2e4f6a8b0c2e4f));

    // -------------------------------------------------------------------------
    // IMMUTABLE STATE
    // -------------------------------------------------------------------------

    address public immutable treasury;
    address public immutable genesisKeeper;
    uint256 public immutable deployBlock;

    // -------------------------------------------------------------------------
    // MUTABLE STATE (access-controlled)
    // -------------------------------------------------------------------------

    address public keeper;
    address public operator;
    uint256 public protocolFeeBasisPoints;
    uint256 public totalSeedsStaked;
    uint256 public totalYieldDistributed;
    uint256 public treasuryBalance;
    uint256 public pendingHarvestBuffer;

    struct LockTier {
        uint256 lockBlocks;
        uint256 weightNumerator;   // for yield distribution
        uint256 totalSeedsInTier;
        uint256 accumulatedYieldPerSeedScaled; // scaled by 1e18
        bool exists;
    }

    struct Chest {
        address owner;
        uint8 tierIndex;
        uint256 seedBalance;
        uint256 unlockBlock;
        uint256 entryAccruedPerSeedScaled; // snapshot at deposit
        uint256 chestId;
        bool active;
    }

    uint8 public tierCount;
    mapping(uint8 => LockTier) public lockTiers;
    mapping(address => uint256) public userChestCount;
    mapping(address => mapping(uint256 => Chest)) public userChests;
    mapping(address => uint256) private _nextChestId;

    // -------------------------------------------------------------------------
    // MODIFIERS
    // -------------------------------------------------------------------------

    modifier onlyKeeper() {
        if (msg.sender != keeper) revert BLM_NotKeeper();
        _;
    }

    modifier onlyOperator() {
        if (msg.sender != operator) revert BLM_NotOperator();
        _;
    }

    modifier whenGardenNotPaused() {
        if (paused()) revert BLM_Paused();
        _;
    }

    // -------------------------------------------------------------------------
    // CONSTRUCTOR
    // -------------------------------------------------------------------------

    constructor() {
        treasury = address(0x5E9a1c3F7b2D4e6A8c0E2f4a6B8d0C2e4F6a8b0D2);
        genesisKeeper = address(0x6F0b2d4E8a1C3e5F7b9D1f3A5c7E9b1D3f5A7c9E1);
        keeper = address(0x6F0b2d4E8a1C3e5F7b9D1f3A5c7E9b1D3f5A7c9E1);
        operator = address(0x7A1c3e5F9b2D4f6A8c0E2a4B6d8F0b2D4f6A8c0E2);
        deployBlock = block.number;
        protocolFeeBasisPoints = 100; // 1%
        _addTierInternal(128, 100);   // ~32 min, weight 100
        _addTierInternal(256, 150);   // ~64 min
        _addTierInternal(1024, 250);  // ~4.3 hrs
        _addTierInternal(4096, 400);  // ~17 hrs
        _addTierInternal(16384, 600); // ~2.8 days
        _addTierInternal(65536, 1000); // ~11 days
    }

    function _addTierInternal(uint256 lockBlocks, uint256 weightNum) internal {
        if (tierCount >= BLOOM_MAX_TIERS) return;
        if (lockBlocks < BLOOM_MIN_LOCK_BLOCKS || lockBlocks > BLOOM_MAX_LOCK_BLOCKS) return;
        lockTiers[tierCount] = LockTier({
            lockBlocks: lockBlocks,
            weightNumerator: weightNum,
            totalSeedsInTier: 0,
            accumulatedYieldPerSeedScaled: 0,
            exists: true
        });
        tierCount++;
    }

    // -------------------------------------------------------------------------
    // OPERATOR: PAUSE
    // -------------------------------------------------------------------------

    /// @notice Pause or unpause all user deposits and harvests. Operator only.
    /// @param _paused True to pause, false to unpause.
    function setPaused(bool _paused) external onlyOperator {
        if (_paused) {
            _pause();
            emit GardenPaused(msg.sender, block.number);
        } else {
            _unpause();
            emit GardenUnpaused(msg.sender, block.number);
        }
    }

    /// @notice Set protocol fee in basis points (max BLOOM_MAX_FEE_BASIS). Operator only.
    /// @param _basis New fee in basis points (e.g. 100 = 1%).
    function setProtocolFeeBasisPoints(uint256 _basis) external onlyOperator {
        if (_basis > BLOOM_MAX_FEE_BASIS) revert BLM_FeeBasisTooHigh();
        uint256 prev = protocolFeeBasisPoints;
        protocolFeeBasisPoints = _basis;
        emit ProtocolFeeBasisSet(prev, _basis, block.number);
    }

    /// @notice Transfer keeper role. Operator only.
    /// @param _newKeeper New keeper address (cannot be zero).
    function setKeeper(address _newKeeper) external onlyOperator {
        if (_newKeeper == address(0)) revert BLM_ZeroAddress();
        address prev = keeper;
        keeper = _newKeeper;
        emit KeeperUpdated(prev, _newKeeper);
    }

    /// @notice Transfer operator role. Operator only.
    /// @param _newOperator New operator address (cannot be zero).
    function setOperator(address _newOperator) external onlyOperator {
        if (_newOperator == address(0)) revert BLM_ZeroAddress();
        address prev = operator;
        operator = _newOperator;
        emit OperatorUpdated(prev, _newOperator);
    }

    // -------------------------------------------------------------------------
    // KEEPER: HARVEST
    // -------------------------------------------------------------------------

    /// @notice Submit new yield (ETH). Fee is taken to treasury; rest goes to pending buffer. Keeper only.
    function harvest() external payable onlyKeeper whenGardenNotPaused nonReentrant {
        if (msg.value == 0) revert BLM_HarvestZero();
        uint256 totalYield = msg.value;
        uint256 fee = (totalYield * protocolFeeBasisPoints) / BLOOM_BASIS_DENOM;
        uint256 toDistribute = totalYield - fee;
        treasuryBalance += fee;
        pendingHarvestBuffer += toDistribute;
        emit YieldHarvested(totalYield, fee, toDistribute, block.number);
    }

    /// @notice Allocate pending harvest buffer to tiers by weight. Call after harvest(). Keeper only.
    function allocateHarvest() external onlyKeeper whenGardenNotPaused nonReentrant {
        uint256 toAlloc = pendingHarvestBuffer;
        if (toAlloc == 0) return;
        uint256 totalWeight = 0;
        for (uint8 i = 0; i < tierCount; i++) {
            if (lockTiers[i].exists && lockTiers[i].totalSeedsInTier > 0) {
                totalWeight += lockTiers[i].weightNumerator;
            }
        }
        if (totalWeight == 0) {
            treasuryBalance += toAlloc;
            pendingHarvestBuffer = 0;
            return;
        }
        pendingHarvestBuffer = 0;
        for (uint8 i = 0; i < tierCount; i++) {
            LockTier storage tier = lockTiers[i];
            if (!tier.exists || tier.totalSeedsInTier == 0) continue;
            uint256 portion = (toAlloc * tier.weightNumerator) / totalWeight;
            uint256 seeds = tier.totalSeedsInTier;
            tier.accumulatedYieldPerSeedScaled += (portion * BLOOM_SCALE) / seeds;
            totalYieldDistributed += portion;
            emit YieldAllocatedToTier(i, portion, block.number);
        }
    }

    /// @notice Keeper can adjust yield weight for a tier (higher weight = more yield share).
    function setTierWeight(uint8 tierIndex, uint256 weightNumerator) external onlyKeeper whenGardenNotPaused {
        if (tierIndex >= tierCount || !lockTiers[tierIndex].exists) revert BLM_InvalidTier();
        if (weightNumerator > BLOOM_MAX_WEIGHT) revert BLM_InvalidWeight();
        uint256 prev = lockTiers[tierIndex].weightNumerator;
        lockTiers[tierIndex].weightNumerator = weightNumerator;
        emit TierWeightUpdated(tierIndex, prev, weightNumerator, block.number);
    }

    // -------------------------------------------------------------------------
    // INTERNAL: SAFE ETH SEND
    // -------------------------------------------------------------------------

    function _sendEth(address to, uint256 amount) internal {
        if (amount == 0) return;
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert BLM_TransferFailed();
    }

    // -------------------------------------------------------------------------
    // USER: OPEN CHEST (create lock bucket)
    // -------------------------------------------------------------------------

    /// @notice Open a single chest for a lock tier. Returns the new chest id.
    function openChest(uint8 tierIndex) external whenGardenNotPaused nonReentrant returns (uint256 chestId) {
        if (tierIndex >= tierCount || !lockTiers[tierIndex].exists) revert BLM_InvalidTier();
        uint256 count = userChestCount[msg.sender];
        if (count >= BLOOM_MAX_CHESTS_PER_USER) revert BLM_MaxChestsPerUser();
        chestId = _nextChestId[msg.sender]++;
        uint256 unlockBlock = block.number + lockTiers[tierIndex].lockBlocks;
        userChests[msg.sender][chestId] = Chest({
            owner: msg.sender,
            tierIndex: tierIndex,
            seedBalance: 0,
            unlockBlock: unlockBlock,
            entryAccruedPerSeedScaled: lockTiers[tierIndex].accumulatedYieldPerSeedScaled,
            chestId: chestId,
            active: true
        });
        userChestCount[msg.sender] = count + 1;
        emit ChestOpened(msg.sender, tierIndex, chestId, unlockBlock, block.number);
        return chestId;
    }

    /// @notice Open multiple chests in one tx. tierIndices length must be <= BLOOM_BATCH_SIZE.
    function openChestBatch(uint8[] calldata tierIndices) external whenGardenNotPaused nonReentrant returns (uint256[] memory chestIds) {
        uint256 n = tierIndices.length;
        if (n == 0 || n > BLOOM_BATCH_SIZE) revert BLM_BatchTooLarge();
        if (userChestCount[msg.sender] + n > BLOOM_MAX_CHESTS_PER_USER) revert BLM_MaxChestsPerUser();
        chestIds = new uint256[](n);
        uint8[] memory tiers = new uint8[](n);
        for (uint256 i = 0; i < n; i++) {
            uint8 ti = tierIndices[i];
            if (ti >= tierCount || !lockTiers[ti].exists) revert BLM_InvalidTier();
            uint256 cid = _nextChestId[msg.sender]++;
            uint256 unlockBlock = block.number + lockTiers[ti].lockBlocks;
            userChests[msg.sender][cid] = Chest({
                owner: msg.sender,
                tierIndex: ti,
                seedBalance: 0,
                unlockBlock: unlockBlock,
                entryAccruedPerSeedScaled: lockTiers[ti].accumulatedYieldPerSeedScaled,
                chestId: cid,
                active: true
            });
            chestIds[i] = cid;
            tiers[i] = ti;
            emit ChestOpened(msg.sender, ti, cid, unlockBlock, block.number);
        }
        userChestCount[msg.sender] += n;
        emit ChestOpenedBatch(msg.sender, chestIds, tiers, block.number);
        return chestIds;
    }

    // -------------------------------------------------------------------------
    // USER: DEPOSIT (seed)
    // -------------------------------------------------------------------------

    /// @notice Deposit ETH into an existing chest. msg.value must match sum of amounts if using batch.
    function seed(uint256 chestId) external payable whenGardenNotPaused nonReentrant {
        if (msg.value == 0) revert BLM_ZeroDeposit();
        Chest storage c = userChests[msg.sender][chestId];
        if (!c.active || c.owner != msg.sender) revert BLM_ChestNotFound();
        LockTier storage tier = lockTiers[c.tierIndex];
        c.seedBalance += msg.value;
        tier.totalSeedsInTier += msg.value;
        totalSeedsStaked += msg.value;
        emit SeedDeposited(msg.sender, chestId, msg.value, c.seedBalance, block.number);
    }

    /// @notice Deposit into multiple chests. amounts length must match chestIds; msg.value must equal sum(amounts).
    function seedBatch(uint256[] calldata chestIds, uint256[] calldata amounts) external payable whenGardenNotPaused nonReentrant {
        uint256 n = chestIds.length;
        if (n == 0 || n > BLOOM_BATCH_SIZE) revert BLM_BatchTooLarge();
        if (amounts.length != n) revert BLM_ArrayLengthMismatch();
        uint256 total = 0;
        for (uint256 i = 0; i < n; i++) {
            total += amounts[i];
        }
        if (msg.value != total) revert BLM_TotalMismatch();
        for (uint256 i = 0; i < n; i++) {
            if (amounts[i] == 0) continue;
            Chest storage c = userChests[msg.sender][chestIds[i]];
            if (!c.active || c.owner != msg.sender) revert BLM_ChestNotFound();
            LockTier storage tier = lockTiers[c.tierIndex];
            c.seedBalance += amounts[i];
            tier.totalSeedsInTier += amounts[i];
            totalSeedsStaked += amounts[i];
            emit SeedDeposited(msg.sender, chestIds[i], amounts[i], c.seedBalance, block.number);
        }
        emit SeedDepositedBatch(msg.sender, chestIds, msg.value, block.number);
    }

    // -------------------------------------------------------------------------
    // USER: WITHDRAW (after unlock)
    // -------------------------------------------------------------------------

    /// @notice Withdraw principal and accrued yield from one chest after unlock.
    function withdraw(uint256 chestId) external nonReentrant whenGardenNotPaused {
        Chest storage c = userChests[msg.sender][chestId];
        if (!c.active || c.owner != msg.sender) revert BLM_ChestNotFound();
        if (block.number < c.unlockBlock) revert BLM_ChestLocked();
        uint256 seeds = c.seedBalance;
        if (seeds == 0) revert BLM_WithdrawZero();
        LockTier storage tier = lockTiers[c.tierIndex];
        uint256 accruedPerSeed = tier.accumulatedYieldPerSeedScaled - c.entryAccruedPerSeedScaled;
        uint256 yieldAmount = (seeds * accruedPerSeed) / BLOOM_SCALE;
        c.seedBalance = 0;
        c.active = false;
        tier.totalSeedsInTier -= seeds;
        totalSeedsStaked -= seeds;
        userChestCount[msg.sender] -= 1;
        uint256 totalOut = seeds + yieldAmount;
        _sendEth(msg.sender, totalOut);
        emit ChestWithdrawn(msg.sender, chestId, seeds, yieldAmount, block.number);
    }

    /// @notice Withdraw multiple chests in one tx. Only unlocked chests are withdrawn.
    function withdrawBatch(uint256[] calldata chestIds) external nonReentrant whenGardenNotPaused {
        uint256 n = chestIds.length;
        if (n == 0 || n > BLOOM_BATCH_SIZE) revert BLM_BatchTooLarge();
        uint256 totalSeedOut = 0;
        uint256 totalYieldOut = 0;
        for (uint256 i = 0; i < n; i++) {
            Chest storage c = userChests[msg.sender][chestIds[i]];
            if (!c.active || c.owner != msg.sender || c.seedBalance == 0) continue;
            if (block.number < c.unlockBlock) continue;
            uint256 seeds = c.seedBalance;
            LockTier storage tier = lockTiers[c.tierIndex];
            uint256 accruedPerSeed = tier.accumulatedYieldPerSeedScaled - c.entryAccruedPerSeedScaled;
            uint256 yieldAmount = (seeds * accruedPerSeed) / BLOOM_SCALE;
            c.seedBalance = 0;
            c.active = false;
            tier.totalSeedsInTier -= seeds;
            totalSeedsStaked -= seeds;
            userChestCount[msg.sender] -= 1;
            totalSeedOut += seeds;
            totalYieldOut += yieldAmount;
            emit ChestWithdrawn(msg.sender, chestIds[i], seeds, yieldAmount, block.number);
        }
        if (totalSeedOut + totalYieldOut > 0) {
            _sendEth(msg.sender, totalSeedOut + totalYieldOut);
        }
        if (totalSeedOut != 0 || totalYieldOut != 0) {
            emit ChestWithdrawnBatch(msg.sender, chestIds, totalSeedOut, totalYieldOut, block.number);
        }
    }

    // -------------------------------------------------------------------------
    // VIEW: PENDING YIELD FOR CHEST
    // -------------------------------------------------------------------------

    /// @notice Returns accrued yield for a user's chest (not yet withdrawn).
    function pendingYield(address user, uint256 chestId) external view returns (uint256) {
        Chest storage c = userChests[user][chestId];
        if (!c.active || c.seedBalance == 0) return 0;
        LockTier storage tier = lockTiers[c.tierIndex];
        uint256 accruedPerSeed = tier.accumulatedYieldPerSeedScaled - c.entryAccruedPerSeedScaled;
        return (c.seedBalance * accruedPerSeed) / BLOOM_SCALE;
    }

    /// @notice Total pending yield across all active chests for a user.
    function getTotalPendingYieldForUser(address user) external view returns (uint256 total) {
        uint256 nextId = _nextChestId[user];
        for (uint256 i = 0; i < nextId; i++) {
            Chest storage c = userChests[user][i];
            if (!c.active || c.seedBalance == 0) continue;
            LockTier storage tier = lockTiers[c.tierIndex];
            uint256 accruedPerSeed = tier.accumulatedYieldPerSeedScaled - c.entryAccruedPerSeedScaled;
            total += (c.seedBalance * accruedPerSeed) / BLOOM_SCALE;
        }
        return total;
    }

    /// @notice List of active chest ids for a user (ids that are active and may have balance).
    function getUserActiveChestIds(address user) external view returns (uint256[] memory ids) {
        uint256 nextId = _nextChestId[user];
        uint256 count = 0;
        for (uint256 i = 0; i < nextId; i++) {
            if (userChests[user][i].active) count++;
        }
        ids = new uint256[](count);
        uint256 j = 0;
        for (uint256 i = 0; i < nextId; i++) {
            if (userChests[user][i].active) {
                ids[j] = i;
                j++;
            }
        }
        return ids;
    }

    /// @notice Full chest snapshot for a user and chest id.
    /// @param user Owner address.
    /// @param chestId Chest id.
    /// @return owner Chest owner (same as user).
    /// @return tierIndex Lock tier index.
    /// @return seedBalance Principal staked in this chest.
    /// @return unlockBlock Block number when chest becomes withdrawable.
    /// @return active True if chest exists and has not been withdrawn.
    function getChest(address user, uint256 chestId) external view returns (
        address owner,
        uint8 tierIndex,
        uint256 seedBalance,
        uint256 unlockBlock,
        bool active
    ) {
        Chest storage c = userChests[user][chestId];
        return (c.owner, c.tierIndex, c.seedBalance, c.unlockBlock, c.active);
    }

    /// @notice Global stats: total staked, total yield distributed, treasury balance, pending harvest buffer.
    /// @return totalStaked Sum of all seed balances in active chests.
    /// @return totalYield Cumulative yield allocated to tiers so far.
    /// @return treasuryBal Protocol fees awaiting withdrawal to treasury.
    /// @return pendingHarvest ETH in buffer not yet allocated to tiers.
    function getGlobalStats() external view returns (
        uint256 totalStaked,
        uint256 totalYield,
        uint256 treasuryBal,
        uint256 pendingHarvest
    ) {
        return (
            totalSeedsStaked,
            totalYieldDistributed,
            treasuryBalance,
            pendingHarvestBuffer
        );
    }

    /// @notice Single tier info.
    /// @param tierIndex Tier index (0 to tierCount-1).
    /// @return lockBlocks Number of blocks seeds are locked.
    /// @return weightNumerator Weight for harvest distribution (relative to other tiers).
    /// @return totalSeedsInTier Total principal in this tier across all chests.
    /// @return accumulatedYieldPerSeedScaled Cumulative yield per seed (scaled by BLOOM_SCALE).
    /// @return exists True if tier was initialized.
    function getTier(uint8 tierIndex) external view returns (
        uint256 lockBlocks,
        uint256 weightNumerator,
        uint256 totalSeedsInTier,
        uint256 accumulatedYieldPerSeedScaled,
        bool exists
    ) {
        LockTier storage t = lockTiers[tierIndex];
        return (
            t.lockBlocks,
            t.weightNumerator,
            t.totalSeedsInTier,
            t.accumulatedYieldPerSeedScaled,
            t.exists
        );
    }

    /// @notice Batch fetch tier data for indices [fromIndex, toIndex). toIndex exclusive.
    /// @param fromIndex First tier index (inclusive).
    /// @param toIndex Last tier index (exclusive); clamped to tierCount.
    /// @return lockBlocksArr Lock duration per tier.
    /// @return weightNumerators Weight per tier.
    /// @return totalSeedsInTierArr Total seeds per tier.
    /// @return accumulatedYieldScaledArr Accumulated yield per seed scaled per tier.
    /// @return existsArr Exists flag per tier.
    function getTiersBatch(uint8 fromIndex, uint8 toIndex) external view returns (
        uint256[] memory lockBlocksArr,
        uint256[] memory weightNumerators,
        uint256[] memory totalSeedsInTierArr,
        uint256[] memory accumulatedYieldScaledArr,
        bool[] memory existsArr
    ) {
        if (toIndex > tierCount) toIndex = tierCount;
        if (fromIndex >= toIndex) {
            return (new uint256[](0), new uint256[](0), new uint256[](0), new uint256[](0), new bool[](0));
        }
        uint256 n = toIndex - fromIndex;
        lockBlocksArr = new uint256[](n);
        weightNumerators = new uint256[](n);
        totalSeedsInTierArr = new uint256[](n);
        accumulatedYieldScaledArr = new uint256[](n);
        existsArr = new bool[](n);
        for (uint256 i = 0; i < n; i++) {
            LockTier storage t = lockTiers[uint8(fromIndex + i)];
            lockBlocksArr[i] = t.lockBlocks;
            weightNumerators[i] = t.weightNumerator;
            totalSeedsInTierArr[i] = t.totalSeedsInTier;
            accumulatedYieldScaledArr[i] = t.accumulatedYieldPerSeedScaled;
            existsArr[i] = t.exists;
        }
        return (lockBlocksArr, weightNumerators, totalSeedsInTierArr, accumulatedYieldScaledArr, existsArr);
    }

    /// @notice Estimate blocks until unlock for a chest (0 if already unlocked).
    function blocksUntilUnlock(address user, uint256 chestId) external view returns (uint256) {
        Chest storage c = userChests[user][chestId];
        if (!c.active) return 0;
        if (block.number >= c.unlockBlock) return 0;
        return c.unlockBlock - block.number;
    }

    /// @notice Total seed balance across all active chests for a user.
    function getTotalSeedsForUser(address user) external view returns (uint256 total) {
        uint256 nextId = _nextChestId[user];
        for (uint256 i = 0; i < nextId; i++) {
            if (userChests[user][i].active) {
                total += userChests[user][i].seedBalance;
            }
        }
        return total;
    }

    /// @notice Full snapshot of all active chests for a user: ids, tiers, balances, unlock blocks, pending yields.
    function getChestsFullForUser(address user) external view returns (
        uint256[] memory chestIds,
        uint8[] memory tierIndices,
        uint256[] memory seedBalances,
        uint256[] memory unlockBlocks,
        uint256[] memory pendingYields
    ) {
        uint256 nextId = _nextChestId[user];
        uint256 count = 0;
        for (uint256 i = 0; i < nextId; i++) {
            if (userChests[user][i].active) count++;
        }
        chestIds = new uint256[](count);
        tierIndices = new uint8[](count);
        seedBalances = new uint256[](count);
