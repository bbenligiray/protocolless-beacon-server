// SPDX-License-Identifier: MIT
pragma solidity 0.8.9;

import "./BeaconServer.sol";
import "./InPlaceMedian.sol";
import "./interfaces/IDapiServer.sol";

contract DapiServer is BeaconServer, InPlaceMedian, IDapiServer {
    /// @param _accessControlRegistry AccessControlRegistry contract address
    /// @param _adminRoleDescription Admin role description
    /// @param _manager Manager address
    constructor(
        address _accessControlRegistry,
        string memory _adminRoleDescription,
        address _manager
    )
        BeaconServer(
            _accessControlRegistry,
            _adminRoleDescription,
            _manager
        )
    {}

    function readCurrentAndUpdatedDapiValue(bytes32[] memory beaconIds)
        external
        override
        returns (int224 currentDapiValue, int224 updatedDapiValue)
    {
        require(msg.sender == address(0), "Sender not zero address");
        bytes32 dapiId = keccak256(abi.encode(["bytes32[]"], [beaconIds]));
        currentDapiValue = dataPoints[dapiId].value;
        updateDapi(beaconIds);
        updatedDapiValue = dataPoints[dapiId].value;
    }

    function updateDapi(bytes32[] memory beaconIds)
        public
        override
        returns (bytes32 dapiId)
    {
        dapiId = keccak256(abi.encodePacked(beaconIds));
        uint256 beaconCount = beaconIds.length;
        int256[] memory values = new int256[](beaconCount);
        for (uint256 ind = 0; ind < beaconCount; ind++) {
            values[ind] = dataPoints[beaconIds[ind]].value;
        }
        int224 updatedDapiValue = int224(computeMedianInPlace(values));
        dataPoints[dapiId] = DataPoint({
            value: updatedDapiValue,
            timestamp: uint32(block.timestamp)
        });
    }
}
