// SPDX-License-Identifier: MIT
pragma solidity 0.8.9;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../whitelist/WhitelistWithManager.sol";
import "./interfaces/IBeaconServer.sol";

/// @title Contract that serves beacons using the Airnode protocol
/// @notice A beacon is a live data point associated with a beacon ID, which is
/// derived from a template ID and additional parameters. This is suitable
/// where the more recent data point is always more favorable, e.g., in the
/// context of an asset price data feed. Another definition of beacons are
/// one-Airnode data feeds that can be used individually or combined to build
/// dAPIs.
/// @dev This contract casts the reported data point to `int224`. If this is
/// a problem (because the reported data may not fit into 224 bits or it is of
/// a completely different type such as `bytes32`), do not use this contract
/// and implement a customized version instead.
/// The contract casts the timestamps to `uint32`, which means it will not work
/// work past-2106 in the current form. If this is an issue, consider casting
/// the timestamps to a larger type.
contract BeaconServer is WhitelistWithManager, IBeaconServer {
    using ECDSA for bytes32;

    struct DataPoint {
        int224 value;
        uint32 timestamp;
    }

    mapping(bytes32 => address) internal templateIdToAirnode;

    mapping(bytes32 => DataPoint) internal dataPoints;

    /// @param _accessControlRegistry AccessControlRegistry contract address
    /// @param _adminRoleDescription Admin role description
    /// @param _manager Manager address
    constructor(
        address _accessControlRegistry,
        string memory _adminRoleDescription,
        address _manager
    )
        WhitelistWithManager(
            _accessControlRegistry,
            _adminRoleDescription,
            _manager
        )
    {}

    /// @notice Called to update a beacon using data signed by the respective
    /// Airnode
    /// @param templateId Template ID
    /// @param parameters Parameters provided by the requester in addition to
    /// the parameters in the template
    /// @param data Response data (a single `int256` encoded as `bytes`)
    /// @param signature Request hash, a timestamp and the response data signed
    /// by the Airnode address
    function updateBeaconWithoutRequest(
        bytes32 templateId,
        bytes calldata parameters,
        bytes calldata data,
        bytes calldata signature
    ) external override {
        (, bytes32 beaconId) = verifySignature(
            templateId,
            parameters,
            data,
            signature
        );
        (int256 decodedData, uint256 decodedTimestamp) = ingestData(
            beaconId,
            data
        );
        emit UpdatedBeaconWithoutRequest(
            beaconId,
            decodedData,
            decodedTimestamp
        );
    }

    /// @notice Called to read the data point
    /// @param dataPointId ID of the data point that will be read
    /// @return value Data point value
    /// @return timestamp Data point timestamp
    function readDataPoint(bytes32 dataPointId)
        external
        view
        override
        returns (int224 value, uint32 timestamp)
    {
        require(
            readerCanReadDataPoint(dataPointId, msg.sender),
            "Sender cannot read beacon"
        );
        DataPoint storage dataPoint = dataPoints[dataPointId];
        return (dataPoint.value, dataPoint.timestamp);
    }

    /// @notice Called to check if a reader is whitelisted to read the data
    /// point
    /// @param dataPointId Data point ID
    /// @param reader Reader address
    /// @return isWhitelisted If the reader is whitelisted
    function readerCanReadDataPoint(bytes32 dataPointId, address reader)
        public
        view
        override
        returns (bool)
    {
        return
            userIsWhitelisted(dataPointId, reader) || reader == address(0);
    }

    /// @notice Called to get the detailed whitelist status of the reader for
    /// the data point
    /// @param dataPointId Data point ID
    /// @param reader Reader address
    /// @return expirationTimestamp Timestamp at which the whitelisting of the
    /// reader will expire
    /// @return indefiniteWhitelistCount Number of times `reader` was
    /// whitelisted indefinitely for `id`
    function dataPointIdToReaderToWhitelistStatus(
        bytes32 dataPointId,
        address reader
    )
        external
        view
        override
        returns (uint64 expirationTimestamp, uint192 indefiniteWhitelistCount)
    {
        WhitelistStatus
            storage whitelistStatus = serviceIdToUserToWhitelistStatus[
                dataPointId
            ][reader];
        expirationTimestamp = whitelistStatus.expirationTimestamp;
        indefiniteWhitelistCount = whitelistStatus.indefiniteWhitelistCount;
    }

    /// @notice Returns if an account has indefinitely whitelisted the reader
    /// for the data point
    /// @param dataPointId Data point ID
    /// @param reader Reader address
    /// @param setter Address of the account that has potentially whitelisted
    /// the reader for the data point indefinitely
    /// @return indefiniteWhitelistStatus If `setter` has indefinitely
    /// whitelisted reader for the data point
    function dataPointIdToReaderToSetterToIndefiniteWhitelistStatus(
        bytes32 dataPointId,
        address reader,
        address setter
    ) external view override returns (bool indefiniteWhitelistStatus) {
        indefiniteWhitelistStatus = serviceIdToUserToSetterToIndefiniteWhitelistStatus[
            dataPointId
        ][reader][setter];
    }

    /// @notice Derives the beacon ID from the respective template ID and
    /// additional parameters
    /// @param templateId Template ID
    /// @param parameters Parameters provided by the requester in addition to
    /// the parameters in the template
    /// @return beaconId Beacon ID
    function deriveBeaconId(bytes32 templateId, bytes memory parameters)
        public
        pure
        override
        returns (bytes32 beaconId)
    {
        beaconId = keccak256(abi.encodePacked(templateId, parameters));
    }

    /// @notice Called privately to decode and process the fulfillment data
    /// @param beaconId Beacon ID
    /// @param data Fulfillment data
    /// @return decodedData Decoded beacon data
    /// @return decodedTimestamp Decoded beacon timestamp
    function ingestData(bytes32 beaconId, bytes calldata data)
        private
        returns (int256 decodedData, uint256 decodedTimestamp)
    {
        require(data.length == 64, "Incorrect data length");
        (decodedData, decodedTimestamp) = abi.decode(data, (int256, uint256));
        require(
            decodedData >= type(int224).min && decodedData <= type(int224).max,
            "Value typecasting error"
        );
        require(
            decodedTimestamp <= type(uint32).max,
            "Timestamp typecasting error"
        );
        require(
            decodedTimestamp > dataPoints[beaconId].timestamp,
            "Fulfillment older than beacon"
        );
        require(
            decodedTimestamp + 1 hours > block.timestamp,
            "Fulfillment stale"
        );
        require(
            decodedTimestamp - 1 hours < block.timestamp,
            "Fulfillment from future"
        );
        dataPoints[beaconId] = DataPoint({
            value: int224(decodedData),
            timestamp: uint32(decodedTimestamp)
        });
    }

    /// @notice Called to verify the fulfillment data associated with a
    /// request, reverts if it fails
    /// @param templateId Template ID
    /// @param parameters Parameters provided by the requester in addition to
    /// the parameters in the template
    /// @param data Fulfillment data
    /// @param signature Request hash and fulfillment data signed by the
    /// Airnode address
    function verifySignature(
        bytes32 templateId,
        bytes calldata parameters,
        bytes calldata data,
        bytes calldata signature
    ) private view returns (address airnode, bytes32 requestHash) {
        airnode = templateIdToAirnode[templateId];
        require(airnode != address(0), "Template not registered");
        requestHash = keccak256(abi.encodePacked(templateId, parameters));
        require(
            (
                keccak256(abi.encodePacked(requestHash, data))
                    .toEthSignedMessageHash()
            ).recover(signature) == airnode,
            "Signature mismatch"
        );
    }

    function registerTemplateId(
        address airnode,
        bytes32 endpointId,
        bytes calldata parameters
    ) external returns (bytes32 templateId) {
        templateId = keccak256(
            abi.encodePacked(airnode, endpointId, parameters)
        );
        templateIdToAirnode[templateId] = airnode;
    }
}
