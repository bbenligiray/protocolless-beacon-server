// SPDX-License-Identifier: MIT
pragma solidity 0.8.9;

interface IDapiReader {
    function dapiServer() external view returns (address);
}

/// @dev We use the part of the interface that will persist between
/// DapiServer versions
interface IBaseDapiServer {
    function readDataPointWithId(bytes32 dataPointId)
        external
        view
        returns (int224 value, uint32 timestamp);

    function readDataPointValueWithId(bytes32 dataPointId)
        external
        view
        returns (int224 value);

    function readDataPointWithName(bytes32 name)
        external
        view
        returns (int224 value, uint32 timestamp);
}
