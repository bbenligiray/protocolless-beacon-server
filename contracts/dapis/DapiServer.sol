// SPDX-License-Identifier: MIT
pragma solidity 0.8.9;

import "../whitelist/WhitelistWithManager.sol";
import "./Median.sol";
import "./interfaces/IDapiServer.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title Contract that serves Beacons, Beacon sets and dAPIs
/// @notice A Beacon is a live data feed addressed by an ID, which is derived
/// from an Airnode address and a template ID. This is suitable where the more
/// recent data point is always more favorable, e.g., in the context of an
/// asset price data feed. Beacons can also be seen as one-Airnode data feeds
/// that can be used individually or combined to build Beacon sets. dAPIs are
/// an abstraction layer over Beacons and Beacon sets.
contract DapiServer is WhitelistWithManager, Median, IDapiServer {
    using ECDSA for bytes32;

    // Airnodes serve their fulfillment data along with timestamps. This
    // contract casts the reported data to `int224` and the timestamp to
    // `uint32`, which works until year 2106.
    struct DataFeed {
        int224 value;
        uint32 timestamp;
    }

    /// @notice Name setter role description
    string public constant override DAPI_NAME_SETTER_ROLE_DESCRIPTION =
        "dAPI name setter";

    /// @notice dAPI name setter role description
    bytes32 public immutable override dapiNameSetterRole;

    /// @notice If an account is an unlimited reader
    mapping(address => bool) public unlimitedReaderStatus;

    mapping(bytes32 => DataFeed) private dataFeeds;

    mapping(bytes32 => bytes32) private dapiNameHashToDataFeedId;

    /// @dev Reverts if the timestamp is not valid
    /// @param timestamp Timestamp used in the signature
    modifier onlyValidTimestamp(uint256 timestamp) {
        require(timestampIsValid(timestamp), "Timestamp not valid");
        _;
    }

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
    {
        dapiNameSetterRole = _deriveRole(
            _deriveAdminRole(manager),
            keccak256(abi.encodePacked(DAPI_NAME_SETTER_ROLE_DESCRIPTION))
        );
    }

    /// @notice Updates a Beacon using data signed by the respective Airnode
    /// @param airnode Airnode address
    /// @param templateId Template ID
    /// @param timestamp Timestamp used in the signature
    /// @param data Response data (an `int256` encoded in contract ABI)
    /// @param signature Template ID, a timestamp and the response data signed
    /// by the Airnode address
    function updateBeaconWithSignedData(
        address airnode,
        bytes32 templateId,
        uint256 timestamp,
        bytes calldata data,
        bytes calldata signature
    ) external override onlyValidTimestamp(timestamp) {
        require(
            (
                keccak256(abi.encodePacked(templateId, timestamp, data))
                    .toEthSignedMessageHash()
            ).recover(signature) == airnode,
            "Signature mismatch"
        );
        bytes32 beaconId = deriveBeaconId(airnode, templateId);
        int256 decodedData = processBeaconUpdate(beaconId, timestamp, data);
        emit UpdatedBeaconWithSignedData(beaconId, decodedData, timestamp);
    }

    /// @notice Updates the Beacon set using the current values of its Beacons
    /// @dev This function still works if some of the IDs in `beaconIds` belong
    /// to Beacon sets rather than Beacons. However, this is not the intended
    /// use.
    /// @param beaconIds Beacon IDs
    /// @return beaconSetId Beacon set ID
    function updateBeaconSetWithBeacons(bytes32[] memory beaconIds)
        public
        override
        returns (bytes32 beaconSetId)
    {
        uint256 beaconCount = beaconIds.length;
        require(beaconCount > 1, "Specified less than two Beacons");
        int256[] memory values = new int256[](beaconCount);
        uint256 accumulatedTimestamp = 0;
        for (uint256 ind = 0; ind < beaconCount; ind++) {
            DataFeed storage dataFeed = dataFeeds[beaconIds[ind]];
            values[ind] = dataFeed.value;
            accumulatedTimestamp += dataFeed.timestamp;
        }
        uint32 updatedTimestamp = uint32(accumulatedTimestamp / beaconCount);
        beaconSetId = deriveBeaconSetId(beaconIds);
        require(
            updatedTimestamp >= dataFeeds[beaconSetId].timestamp,
            "Updated value outdated"
        );
        int224 updatedValue = int224(median(values));
        dataFeeds[beaconSetId] = DataFeed({
            value: updatedValue,
            timestamp: updatedTimestamp
        });
        emit UpdatedBeaconSetWithBeacons(
            beaconSetId,
            updatedValue,
            updatedTimestamp
        );
    }

    /// @notice Updates a Beacon set using data signed by the respective
    /// Airnodes. The Beacons for which the signature is omitted will be read
    /// from the storage.
    /// @param airnodes Airnode addresses
    /// @param templateIds Template IDs
    /// @param timestamps Timestamps used in the signatures
    /// @param data Response data (an `int256` encoded in contract ABI per
    /// Beacon)
    /// @param signatures Template ID, a timestamp and the response data signed
    /// by the respective Airnode address per Beacon
    /// @return beaconSetId Beacon set ID
    function updateBeaconSetWithSignedData(
        address[] memory airnodes,
        bytes32[] memory templateIds,
        uint256[] memory timestamps,
        bytes[] memory data,
        bytes[] memory signatures
    ) external override returns (bytes32 beaconSetId) {
        uint256 beaconCount = airnodes.length;
        require(
            beaconCount == templateIds.length &&
                beaconCount == timestamps.length &&
                beaconCount == data.length &&
                beaconCount == signatures.length,
            "Parameter length mismatch"
        );
        require(beaconCount > 1, "Specified less than two Beacons");
        bytes32[] memory beaconIds = new bytes32[](beaconCount);
        int256[] memory values = new int256[](beaconCount);
        uint256 accumulatedTimestamp = 0;
        for (uint256 ind = 0; ind < beaconCount; ind++) {
            if (signatures[ind].length != 0) {
                address airnode = airnodes[ind];
                uint256 timestamp = timestamps[ind];
                require(timestampIsValid(timestamp), "Timestamp not valid");
                require(
                    (
                        keccak256(
                            abi.encodePacked(
                                templateIds[ind],
                                timestamp,
                                data[ind]
                            )
                        ).toEthSignedMessageHash()
                    ).recover(signatures[ind]) == airnode,
                    "Signature mismatch"
                );
                values[ind] = decodeFulfillmentData(data[ind]);
                // Timestamp validity is already checked, which means it will
                // be small enough to be typecast into `uint32`
                accumulatedTimestamp += timestamp;
                beaconIds[ind] = deriveBeaconId(airnode, templateIds[ind]);
            } else {
                bytes32 beaconId = deriveBeaconId(
                    airnodes[ind],
                    templateIds[ind]
                );
                DataFeed storage dataFeed = dataFeeds[beaconId];
                values[ind] = dataFeed.value;
                accumulatedTimestamp += dataFeed.timestamp;
                beaconIds[ind] = beaconId;
            }
        }
        beaconSetId = deriveBeaconSetId(beaconIds);
        uint32 updatedTimestamp = uint32(accumulatedTimestamp / beaconCount);
        require(
            updatedTimestamp >= dataFeeds[beaconSetId].timestamp,
            "Updated value outdated"
        );
        int224 updatedValue = int224(median(values));
        dataFeeds[beaconSetId] = DataFeed({
            value: updatedValue,
            timestamp: updatedTimestamp
        });
        emit UpdatedBeaconSetWithSignedData(
            beaconSetId,
            updatedValue,
            updatedTimestamp
        );
    }

    /// @notice Called by the manager to add the unlimited reader indefinitely
    /// @dev Since the unlimited reader status cannot be revoked, only
    /// contracts that are adequately restricted should be given this status
    /// @param unlimitedReader Unlimited reader address
    function addUnlimitedReader(address unlimitedReader) external override {
        require(msg.sender == manager, "Sender not manager");
        unlimitedReaderStatus[unlimitedReader] = true;
        emit AddedUnlimitedReader(unlimitedReader);
    }

    /// @notice Sets the data feed ID the dAPI name points to
    /// @dev While a data feed ID refers to a specific Beacon or Beacon set,
    /// dAPI names provide a more abstract interface for convenience. This
    /// means a dAPI name that was pointing to a Beacon can be pointed to a
    /// Beacon set, then another Beacon set, etc.
    /// @param dapiName Human-readable dAPI name
    /// @param dataFeedId Data feed ID the dAPI name will point to
    function setDapiName(bytes32 dapiName, bytes32 dataFeedId)
        external
        override
    {
        require(dapiName != bytes32(0), "dAPI name zero");
        require(
            msg.sender == manager ||
                IAccessControlRegistry(accessControlRegistry).hasRole(
                    dapiNameSetterRole,
                    msg.sender
                ),
            "Sender cannot set dAPI name"
        );
        dapiNameHashToDataFeedId[
            keccak256(abi.encodePacked(dapiName))
        ] = dataFeedId;
        emit SetDapiName(dapiName, dataFeedId, msg.sender);
    }

    /// @notice Returns the data feed ID the dAPI name is set to
    /// @param dapiName dAPI name
    /// @return Data feed ID
    function dapiNameToDataFeedId(bytes32 dapiName)
        external
        view
        override
        returns (bytes32)
    {
        return dapiNameHashToDataFeedId[keccak256(abi.encodePacked(dapiName))];
    }

    /// @notice Reads the data feed with ID
    /// @param dataFeedId Data feed ID
    /// @return value Data feed value
    /// @return timestamp Data feed timestamp
    function readDataFeedWithId(bytes32 dataFeedId)
        external
        view
        override
        returns (int224 value, uint32 timestamp)
    {
        require(
            readerCanReadDataFeed(dataFeedId, msg.sender),
            "Sender cannot read"
        );
        DataFeed storage dataFeed = dataFeeds[dataFeedId];
        return (dataFeed.value, dataFeed.timestamp);
    }

    /// @notice Reads the data feed value with ID
    /// @param dataFeedId Data feed ID
    /// @return value Data feed value
    function readDataFeedValueWithId(bytes32 dataFeedId)
        external
        view
        override
        returns (int224 value)
    {
        require(
            readerCanReadDataFeed(dataFeedId, msg.sender),
            "Sender cannot read"
        );
        DataFeed storage dataFeed = dataFeeds[dataFeedId];
        require(dataFeed.timestamp != 0, "Data feed does not exist");
        return dataFeed.value;
    }

    /// @notice Reads the data feed with dAPI name
    /// @dev The read data feed may belong to a Beacon or dAPI. The reader
    /// must be whitelisted for the hash of the dAPI name.
    /// @param dapiName dAPI name
    /// @return value Data feed value
    /// @return timestamp Data feed timestamp
    function readDataFeedWithDapiName(bytes32 dapiName)
        external
        view
        override
        returns (int224 value, uint32 timestamp)
    {
        bytes32 dapiNameHash = keccak256(abi.encodePacked(dapiName));
        require(
            readerCanReadDataFeed(dapiNameHash, msg.sender),
            "Sender cannot read"
        );
        bytes32 dataFeedId = dapiNameHashToDataFeedId[dapiNameHash];
        require(dataFeedId != bytes32(0), "dAPI name not set");
        DataFeed storage dataFeed = dataFeeds[dataFeedId];
        return (dataFeed.value, dataFeed.timestamp);
    }

    /// @notice Reads the data feed value with dAPI name
    /// @param dapiName dAPI name
    /// @return value Data feed value
    function readDataFeedValueWithDapiName(bytes32 dapiName)
        external
        view
        override
        returns (int224 value)
    {
        bytes32 dapiNameHash = keccak256(abi.encodePacked(dapiName));
        require(
            readerCanReadDataFeed(dapiNameHash, msg.sender),
            "Sender cannot read"
        );
        DataFeed storage dataFeed = dataFeeds[
            dapiNameHashToDataFeedId[dapiNameHash]
        ];
        require(dataFeed.timestamp != 0, "Data feed does not exist");
        return dataFeed.value;
    }

    /// @notice Returns if a reader can read the data feed
    /// @param dataFeedId Data feed ID (or dAPI name hash)
    /// @param reader Reader address
    /// @return If the reader can read the data feed
    function readerCanReadDataFeed(bytes32 dataFeedId, address reader)
        public
        view
        override
        returns (bool)
    {
        return
            reader == address(0) ||
            userIsWhitelisted(dataFeedId, reader) ||
            unlimitedReaderStatus[reader];
    }

    /// @notice Returns the detailed whitelist status of the reader for the
    /// data feed
    /// @param dataFeedId Data feed ID (or dAPI name hash)
    /// @param reader Reader address
    /// @return expirationTimestamp Timestamp at which the whitelisting of the
    /// reader will expire
    /// @return indefiniteWhitelistCount Number of times `reader` was
    /// whitelisted indefinitely for `dataFeedId`
    function dataFeedIdToReaderToWhitelistStatus(
        bytes32 dataFeedId,
        address reader
    )
        external
        view
        override
        returns (uint64 expirationTimestamp, uint192 indefiniteWhitelistCount)
    {
        WhitelistStatus
            storage whitelistStatus = serviceIdToUserToWhitelistStatus[
                dataFeedId
            ][reader];
        expirationTimestamp = whitelistStatus.expirationTimestamp;
        indefiniteWhitelistCount = whitelistStatus.indefiniteWhitelistCount;
    }

    /// @notice Returns if an account has indefinitely whitelisted the reader
    /// for the data feed
    /// @param dataFeedId Data feed ID (or dAPI name hash)
    /// @param reader Reader address
    /// @param setter Address of the account that has potentially whitelisted
    /// the reader for the data feed indefinitely
    /// @return indefiniteWhitelistStatus If `setter` has indefinitely
    /// whitelisted reader for the data feed
    function dataFeedIdToReaderToSetterToIndefiniteWhitelistStatus(
        bytes32 dataFeedId,
        address reader,
        address setter
    ) external view override returns (bool indefiniteWhitelistStatus) {
        indefiniteWhitelistStatus = serviceIdToUserToSetterToIndefiniteWhitelistStatus[
            dataFeedId
        ][reader][setter];
    }

    /// @notice Derives the Beacon ID from the Airnode address and template ID
    /// @param airnode Airnode address
    /// @param templateId Template ID
    /// @return beaconId Beacon ID
    function deriveBeaconId(address airnode, bytes32 templateId)
        public
        pure
        override
        returns (bytes32 beaconId)
    {
        require(airnode != address(0), "Airnode address zero");
        require(templateId != bytes32(0), "Template ID zero");
        beaconId = keccak256(abi.encodePacked(airnode, templateId));
    }

    /// @notice Derives the Beacon set ID from the Beacon IDs
    /// @dev Notice that `abi.encode()` is used over `abi.encodePacked()`
    /// @param beaconIds Beacon IDs
    /// @return beaconSetId Beacon set ID
    function deriveBeaconSetId(bytes32[] memory beaconIds)
        public
        pure
        override
        returns (bytes32 beaconSetId)
    {
        beaconSetId = keccak256(abi.encode(beaconIds));
    }

    /// @notice Called privately to process the Beacon update
    /// @param beaconId Beacon ID
    /// @param timestamp Timestamp used in the signature
    /// @param data Fulfillment data (an `int256` encoded in contract ABI)
    /// @return updatedBeaconValue Updated Beacon value
    function processBeaconUpdate(
        bytes32 beaconId,
        uint256 timestamp,
        bytes calldata data
    ) private returns (int256 updatedBeaconValue) {
        updatedBeaconValue = decodeFulfillmentData(data);
        require(
            timestamp > dataFeeds[beaconId].timestamp,
            "Fulfillment older than Beacon"
        );
        // Timestamp validity is already checked by `onlyValidTimestamp`, which
        // means it will be small enough to be typecast into `uint32`
        dataFeeds[beaconId] = DataFeed({
            value: int224(updatedBeaconValue),
            timestamp: uint32(timestamp)
        });
    }

    /// @notice Called privately to decode the fulfillment data
    /// @param data Fulfillment data (an `int256` encoded in contract ABI)
    /// @return decodedData Decoded fulfillment data
    function decodeFulfillmentData(bytes memory data)
        private
        pure
        returns (int224)
    {
        require(data.length == 32, "Data length not correct");
        int256 decodedData = abi.decode(data, (int256));
        require(
            decodedData >= type(int224).min && decodedData <= type(int224).max,
            "Value typecasting error"
        );
        return int224(decodedData);
    }

    /// @notice Returns if the timestamp used in the signature is valid
    /// @dev Returns `false` if the timestamp is not at most 1 hour old to
    /// prevent replays. Returns `false` if the timestamp is not from the past,
    /// with some leeway to accomodate for some benign time drift. These values
    /// are appropriate in most cases, but you can adjust them if you are aware
    /// of the implications.
    /// @param timestamp Timestamp used in the signature
    function timestampIsValid(uint256 timestamp) private view returns (bool) {
        return
            timestamp + 1 hours > block.timestamp &&
            timestamp < block.timestamp + 15 minutes;
    }
}
