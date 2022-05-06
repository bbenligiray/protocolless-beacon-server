// SPDX-License-Identifier: MIT
pragma solidity 0.8.9;

interface IDapiServer {
    event UpdatedBeaconWithSignedData(
        bytes32 indexed beaconId,
        int256 value,
        uint256 timestamp
    );

    event UpdatedBeaconSetWithBeacons(
        bytes32 indexed beaconSetId,
        int224 value,
        uint32 timestamp
    );

    event UpdatedBeaconSetWithSignedData(
        bytes32 indexed dapiId,
        int224 value,
        uint32 timestamp
    );

    function updateBeaconWithSignedData(
        address airnode,
        bytes32 beaconId,
        uint256 timestamp,
        bytes calldata data,
        bytes calldata signature
    ) external;

    function updateBeaconSetWithBeacons(bytes32[] memory beaconIds)
        external
        returns (bytes32 beaconSetId);

    function updateBeaconSetWithSignedData(
        address[] memory airnodes,
        bytes32[] memory templateIds,
        uint256[] memory timestamps,
        bytes[] memory data,
        bytes[] memory signatures
    ) external returns (bytes32 beaconSetId);

    function readDataFeedWithId(bytes32 dataFeedId)
        external
        view
        returns (int224 value, uint32 timestamp);

    function readDataFeedValueWithId(bytes32 dataFeedId)
        external
        view
        returns (int224 value);

    function deriveBeaconId(address airnode, bytes32 templateId)
        external
        pure
        returns (bytes32 beaconId);

    function deriveBeaconSetId(bytes32[] memory beaconIds)
        external
        pure
        returns (bytes32 beaconSetId);
}
