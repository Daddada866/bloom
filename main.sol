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
