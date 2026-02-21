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
