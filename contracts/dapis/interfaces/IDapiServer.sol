// SPDX-License-Identifier: MIT
pragma solidity 0.8.9;

interface IDapiServer {
    event UpdatedBeaconWithSignedData(
        bytes32 indexed beaconId,
        int256 value,
        uint256 timestamp
    );

    event UpdatedDapiWithBeacons(
        bytes32 indexed dapiId,
        int224 value,
        uint32 timestamp
    );

    event UpdatedDapiWithSignedData(
        bytes32 indexed dapiId,
        int224 value,
        uint32 timestamp
    );

    event SetName(
        bytes32 indexed name,
        bytes32 dataPointId,
        address indexed sender
    );

    function updateBeaconWithSignedData(
        address airnode,
        bytes32 beaconId,
        uint256 timestamp,
        bytes calldata data,
        bytes calldata signature
    ) external;

    function updateDapiWithBeacons(bytes32[] memory beaconIds)
        external
        returns (bytes32 dapiId);

    function updateDapiWithSignedData(
        address[] memory airnodes,
        bytes32[] memory templateIds,
        uint256[] memory timestamps,
        bytes[] memory data,
        bytes[] memory signatures
    ) external returns (bytes32 dapiId);

    function setName(bytes32 name, bytes32 dataPointId) external;

    function nameToDataPointId(bytes32 name) external view returns (bytes32);

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

    function deriveBeaconId(address airnode, bytes32 templateId)
        external
        pure
        returns (bytes32 beaconId);

    function deriveDapiId(bytes32[] memory beaconIds)
        external
        pure
        returns (bytes32 dapiId);

    // solhint-disable-next-line func-name-mixedcase
    function UNLIMITED_READER_ROLE_DESCRIPTION()
        external
        view
        returns (string memory);

    // solhint-disable-next-line func-name-mixedcase
    function NAME_SETTER_ROLE_DESCRIPTION()
        external
        view
        returns (string memory);

    function unlimitedReaderRole() external view returns (bytes32);

    function nameSetterRole() external view returns (bytes32);
}
