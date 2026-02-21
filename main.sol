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
