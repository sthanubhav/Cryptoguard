// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FileStorage {
    struct File {
        string url;
        uint256 timestamp;
    }

    mapping(string => File) private files;

    event FileUploaded(string hash, string url, uint256 timestamp);

    // Function to upload a file
    function uploadFile(string memory hash, string memory url) public {
        require(bytes(hash).length > 0, "Hash must not be empty");
        require(bytes(url).length > 0, "URL must not be empty");
        require(files[hash].timestamp == 0, "File with the same hash already exists");

        files[hash] = File(url, block.timestamp);

        emit FileUploaded(hash, url, block.timestamp);
    }

    // Function to get a file URL using its hash
    function getFile(string memory hash) public view returns (string memory) {
        require(files[hash].timestamp > 0, "File with the given hash does not exist");
        return files[hash].url;
    }
}
