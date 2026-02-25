// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { ModeCode, CallType, CALLTYPE_SINGLE, CALLTYPE_BATCH } from
    "modulekit/accounts/common/lib/ModeLib.sol";
import { ExecutionLib as ERC7579ExecutionLib, Execution } from
    "modulekit/accounts/erc7579/lib/ExecutionLib.sol";

/// @dev Minimal mock ERC-7579 smart account that supports executeFromExecutor.
///      Only allows calls from installed executor modules.
contract MockSmartAccount {
    mapping(address => bool) public installedExecutors;
    mapping(address => bool) public installedValidators;

    receive() external payable { }

    function installExecutor(address executor) external {
        installedExecutors[executor] = true;
        // Call onInstall with empty data (idempotent for multi-type)
        (bool ok,) = executor.call(abi.encodeWithSignature("onInstall(bytes)", ""));
        require(ok, "onInstall failed");
    }

    function installValidator(address validator, bytes memory data) external {
        installedValidators[validator] = true;
        (bool ok,) = validator.call(abi.encodeWithSignature("onInstall(bytes)", data));
        require(ok, "onInstall failed");
    }

    function executeFromExecutor(
        ModeCode mode,
        bytes calldata executionCalldata
    )
        external
        payable
        returns (bytes[] memory returnData)
    {
        require(installedExecutors[msg.sender], "not installed executor");

        CallType callType = CallType.wrap(bytes1(ModeCode.unwrap(mode)));

        if (CallType.unwrap(callType) == CallType.unwrap(CALLTYPE_SINGLE)) {
            (address target, uint256 value, bytes calldata data) =
                ERC7579ExecutionLib.decodeSingle(executionCalldata);
            returnData = new bytes[](1);
            (bool ok, bytes memory result) = target.call{ value: value }(data);
            require(ok, "execution failed");
            returnData[0] = result;
        } else if (CallType.unwrap(callType) == CallType.unwrap(CALLTYPE_BATCH)) {
            Execution[] calldata execs = ERC7579ExecutionLib.decodeBatch(executionCalldata);
            returnData = new bytes[](execs.length);
            for (uint256 i; i < execs.length; i++) {
                (bool ok, bytes memory result) = execs[i].target.call{ value: execs[i].value }(execs[i].callData);
                require(ok, "batch execution failed");
                returnData[i] = result;
            }
        } else {
            revert("unsupported call type");
        }
    }
}
