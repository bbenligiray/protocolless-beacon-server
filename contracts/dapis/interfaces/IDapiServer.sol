// SPDX-License-Identifier: MIT
pragma solidity 0.8.9;

import "./IBeaconServer.sol";

interface IDapiServer is IBeaconServer {
    function readCurrentAndUpdatedDapiValue(bytes32[] memory beaconIds)
        external
        returns (int224 currentDapiValue, int224 updatedDapiValue);
  
    function updateDapi(bytes32[] memory beaconIds)
        external
        returns (bytes32 dapiId);
}
