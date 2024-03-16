// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

import { SignUpGatekeeper } from "./SignUpGatekeeper.sol";

import { IWorldID } from "../interfaces/IWorldID.sol";
import { ByteHasher } from '../lib/ByteHasher.sol';

/// @title WorldIDGatekeeper
/// @notice This contract allows to gatekeep MACI signups
/// by requiring new voters to have a valid World ID
contract WorldIDGatekeeper is SignUpGatekeeper, Ownable {
  using ByteHasher for bytes;

  /// @notice The address of the World ID Router contract that will be used for verifying proofs
  IWorldID internal immutable worldId;

  /// @notice the reference to the MACI contract
  address public maci;

  /// @notice The World ID group ID (1 for Orb-verified)
  uint256 internal immutable groupId = 1;

  /// @notice a mapping of nullifiers to whether they have been used to sign up
  mapping(uint256 => bool) public nullifierHashes;

  /// @notice The keccak256 hash of the externalNullifier (unique identifier of the action performed), combination of appId and action
  uint256 internal immutable externalNullifierHash;

  /// @notice custom errors
  error AlreadyRegistered();
  error NotVerified();
  error OnlyMACI();

  /// @param _worldId The address of the WorldIDRouter that will verify the proofs
  /// @param _appId The World ID App ID (from Developer Portal)
  /// @param _action The World ID Action (from Developer Portal)
  constructor(IWorldID _worldId, string memory _appId, string memory _action) Ownable() {
    worldId = _worldId;
    externalNullifierHash = abi.encodePacked(abi.encodePacked(_appId).hashToField(), _action).hashToField();
  }

  /// @notice Adds an uninitialised MACI instance to allow for token signups
  /// @param _maci The MACI contract interface to be stored
  function setMaciInstance(address _maci) public override onlyOwner {
    maci = _maci;
  }

  /// @notice Registers the user if they own the token with the token ID encoded in
  /// _data. Throws if the user does not own the token or if the token has
  /// already been used to sign up.
  /// @param _user The user's Ethereum address.
  /// @param _data The ABI-encoded World ID proof.
  function register(address _user, bytes memory _data) public override {
    if (maci != msg.sender) revert OnlyMACI();
    // Decode the given _data bytes
    (uint256 root, uint256 nullifierHash, uint256[8] memory proof) = abi.decode(_data, (uint256, uint256, uint256[8]));

    // Make sure this person hasn't done this before
    if (nullifierHashes[nullifierHash]) revert AlreadyRegistered();

    // Verify the provided proof is valid and the user is verified by World ID
    worldId.verifyProof(
      root,
      groupId,
      abi.encodePacked(_user).hashToField(),
      nullifierHash,
      externalNullifierHash,
      proof
    );

    // We now record the user has done this, so they can't do it again (sybil-resistance)
    nullifierHashes[nullifierHash] = true;
  }
}
