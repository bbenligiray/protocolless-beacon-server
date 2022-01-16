// SPDX-License-Identifier: MIT
pragma solidity 0.8.9;

interface IBeaconServer {
    event UpdatedBeaconWithoutRequest(
        bytes32 indexed beaconId,
        int256 value,
        uint256 timestamp
    );

    function updateBeaconWithoutRequest(
        bytes32 templateId,
        bytes calldata parameters,
        bytes calldata data,
        bytes calldata signature
    ) external;

    function readDataPoint(bytes32 dataPointId)
        external
        view
        returns (int224 value, uint32 timestamp);

    function readerCanReadDataPoint(bytes32 dataPointId, address reader)
        external
        view
        returns (bool);

    function dataPointIdToReaderToWhitelistStatus(
        bytes32 dataPointId,
        address reader
    )
        external
        view
        returns (uint64 expirationTimestamp, uint192 indefiniteWhitelistCount);

    function dataPointIdToReaderToSetterToIndefiniteWhitelistStatus(
        bytes32 dataPointId,
        address reader,
        address setter
    ) external view returns (bool indefiniteWhitelistStatus);

    function deriveBeaconId(bytes32 templateId, bytes memory parameters)
        external
        pure
        returns (bytes32 beaconId);
}
