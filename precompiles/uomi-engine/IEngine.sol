// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
/**
 * @title UOMI-ENGINE interface.
 */
/// Interface to the precompiled contract
/// Predeployed at the address 0x00000000000000000000000000000000756f6D69
/// For better understanding check the source code:
/// code: pallets/uomi-engine/src/lib.rs
interface IEngine {
     /**
     * @notice Calls an agent with the specified parameters.
     * @param requestId The unique identifier for the request.
     * @param nftId The unique identifier for the NFT.
     * @param sender The address of the sender initiating the call.
     * @param data The calldata to be passed to the agent.
     * @param inputCid The content identifier for the input data (0x if none).
     * @param minValidators The minimum number of validators required.
     * @param minBlocks The minimum number of blocks required for execution.
     */
    function call_agent(
        uint256 requestId, uint256 nftId, address sender, bytes calldata data, bytes calldata inputCid, uint256 minValidators, uint256 minBlocks
    ) external;
    /**
     * @notice Retrieves the output associated with a given request ID.
     * @param requestId The unique identifier for the request.
     * @return A tuple containing:
     *         - A bytes array representing the output data.
     *         - A uint256 representing the first additional output value.
     *         - A uint256 representing the second additional output value.
     */
    function get_output(uint256 requestId) external view returns (bytes memory, uint256, uint256);
}