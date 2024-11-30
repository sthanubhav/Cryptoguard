// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AdminLogger {
    // Struct to represent an admin action log
    struct Log {
        uint timestamp;
        address user;
        uint level;
        string message;
        string traceback;
    }

    // Array to store admin action logs
    Log[] public logs;

    // Event emitted when a new admin action log is added
    event LogAdded(uint indexed index, uint timestamp, address indexed user, uint level, string message, string traceback);
    // Event emitted when a log is edited
    event LogEdited(uint indexed index, address indexed editor, string oldMessage, string newMessage);
    // Event emitted when a log is deleted
    event LogDeleted(uint indexed index, address indexed deleter, uint deletedTimestamp, uint level, string message, string traceback);

    // Function to add a new admin action log
    function addLog(uint _level, string memory _message, string memory _traceback) public {
        logs.push(Log(block.timestamp, msg.sender, _level, _message, _traceback));
        emit LogAdded(logs.length - 1, block.timestamp, msg.sender, _level, _message, _traceback);
    }

    // Function to edit a log entry
    function editLog(uint index, string memory newMessage) public {
        require(index < logs.length, "Index out of bounds");
        require(msg.sender == logs[index].user, "Only the log creator can edit the log");

        // Store the previous message for auditing purposes
        string memory oldMessage = logs[index].message;

        // Update the log message
        logs[index].message = newMessage;

        // Emit an event to record the edit
        emit LogEdited(index, msg.sender, oldMessage, newMessage);
    }

    // Function to delete a log entry
    function deleteLog(uint index) public {
        require(index < logs.length, "Index out of bounds");
        require(msg.sender == logs[index].user, "Only the log creator can delete the log");

        // Store the log details for auditing purposes
        uint deletedTimestamp = logs[index].timestamp;
        uint level = logs[index].level;
        string memory message = logs[index].message;
        string memory traceback = logs[index].traceback;
        address deleter = msg.sender;

        // Remove the log entry from the array by moving the last element into the deleted position
        logs[index] = logs[logs.length - 1];
        logs.pop();

        // Emit an event to record the deletion
        emit LogDeleted(index, deleter, deletedTimestamp, level, message, traceback);
    }

    // Function to get the total number of admin action logs
    function getLogsCount() public view returns (uint) {
        return logs.length;
    }

    // Function to get admin action log details by index
    function getLog(uint index) public view returns (uint timestamp, address user, uint level, string memory message, string memory traceback) {
        require(index < logs.length, "Index out of bounds");
        Log memory log = logs[index];
        return (log.timestamp, log.user, log.level, log.message, log.traceback);
    }

    // Function to get all logs
    function getAllLogs() public view returns (Log[] memory) {
        return logs;
    }
}
