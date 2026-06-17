/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#pragma once

#include <aws/access-management/AccessManagement_EXPORTS.h>
#include <aws/core/utils/memory/AWSMemory.h>
#include <aws/core/utils/memory/stl/AWSString.h>

#include <functional>
#include <optional>

namespace Aws
{

namespace CognitoIdentity
{
    class CognitoIdentityClient;
} // namespace CognitoIdentity

namespace IAM
{
    class IAMClient;

    namespace Model
    {
        class Group;
        class Policy;
        class Role;
        class User;
    } // namespace Model
} // namespace IAM

namespace AccessManagement
{

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Three-way result distinguishing a successful negative answer (NO) from a
/// missing entity (NOT_FOUND) and an API/network error (FAILURE).
enum class QueryResult
{
    YES,        ///< Condition is true (entity exists, policy is attached, etc.)
    NO,         ///< Condition is false (entity exists but condition is not met)
    NOT_FOUND,  ///< The referenced entity does not exist
    FAILURE     ///< An API or network error occurred
};

enum class IdentityPoolRoleBindingType
{
    AUTHENTICATED,
    UNAUTHENTICATED
};

// ---------------------------------------------------------------------------
// Utility free functions
// ---------------------------------------------------------------------------

/// Extracts the 12-digit AWS account ID from an ARN string.
/// Returns an empty string if @p arn is malformed.
/// Declared as a free function because it has no dependency on client state.
AWS_ACCESS_MANAGEMENT_API Aws::String ExtractAccountIdFromArn(const Aws::String& arn);

// ---------------------------------------------------------------------------
// AccessManagementClient
// ---------------------------------------------------------------------------

/**
 * A high-level client that combines IAM and Cognito Identity operations into
 * convenient compound workflows (GetOrCreate*, *IfNot) while also exposing
 * the underlying primitive operations.
 *
 * Thread-safety: instances are NOT thread-safe. Callers are responsible for
 * external synchronisation if a single instance is shared across threads.
 */
class AWS_ACCESS_MANAGEMENT_API AccessManagementClient
{
public:

    using PolicyGeneratorFunction = std::function<Aws::String()>;

    /// Constructs the client from pre-built sub-clients.
    /// Both pointers must be non-null for the lifetime of this object.
    /// Passed by value so both lvalue and rvalue shared_ptrs are accepted;
    /// the constructor moves them into member storage (one ref-count bump).
    AccessManagementClient(
        std::shared_ptr<Aws::IAM::IAMClient>                          iamClient,
        std::shared_ptr<Aws::CognitoIdentity::CognitoIdentityClient>  cognitoClient);

    ~AccessManagementClient() = default;

    // Non-copyable: the client manages live connections to AWS services.
    // Moving is safe because the underlying shared_ptrs support it.
    AccessManagementClient(const AccessManagementClient&)            = delete;
    AccessManagementClient& operator=(const AccessManagementClient&) = delete;
    AccessManagementClient(AccessManagementClient&&)                 = default;
    AccessManagementClient& operator=(AccessManagementClient&&)      = default;

    // -----------------------------------------------------------------------
    // Account
    // -----------------------------------------------------------------------

    [[nodiscard]] Aws::String GetAccountId() const;

    // -----------------------------------------------------------------------
    // Compound IAM operations
    // -----------------------------------------------------------------------
    //
    // These methods perform a "get or create" pattern: they first query for
    // the entity and create it only if absent. They return true on success
    // and false only when an unrecoverable API error occurs.

    [[nodiscard]] bool GetOrCreateGroup (const Aws::String& groupName,  Aws::IAM::Model::Group&  outGroupData);
    [[nodiscard]] bool GetOrCreatePolicy(const Aws::String& policyName, const PolicyGeneratorFunction& policyGenerator, Aws::IAM::Model::Policy& outPolicyData);
    [[nodiscard]] bool GetOrCreateRole  (const Aws::String& roleName,   const PolicyGeneratorFunction& assumedPolicyGenerator, Aws::IAM::Model::Role& outRoleData);
    [[nodiscard]] bool GetOrCreateUser  (const Aws::String& userName,   Aws::IAM::Model::User&   outUserData);

    /// Attaches @p policyData to the named principal only when not already
    /// attached. Returns true if the policy is attached after the call
    /// (regardless of whether this call did the attaching), false on failure.
    [[nodiscard]] bool AttachPolicyToGroupIfNot(const Aws::IAM::Model::Policy& policyData, const Aws::String& groupName);
    [[nodiscard]] bool AttachPolicyToRoleIfNot (const Aws::IAM::Model::Policy& policyData, const Aws::String& roleName);
    [[nodiscard]] bool AttachPolicyToUserIfNot (const Aws::IAM::Model::Policy& policyData, const Aws::String& userName);

    [[nodiscard]] bool AddUserToGroupIfNot(const Aws::String& userName, const Aws::String& groupName);

    /// Creates a credentials file for @p userName if one does not already
    /// exist at @p credentialsFilename. Returns false on API failure.
    [[nodiscard]] bool VerifyOrCreateCredentialsFileForUser(
        const Aws::String& credentialsFilename,
        const Aws::String& userName);

    // -----------------------------------------------------------------------
    // Compound Cognito operations
    // -----------------------------------------------------------------------

    [[nodiscard]] bool GetOrCreateIdentityPool(
        const Aws::String& poolName,
        bool               allowUnauthenticatedIdentities,
        Aws::String&       outIdentityPoolId);

    [[nodiscard]] bool BindRoleToIdentityPoolIfNot(
        const Aws::String&          identityPoolId,
        const Aws::String&          roleArn,
        IdentityPoolRoleBindingType roleKey);

    // -----------------------------------------------------------------------
    // Simple IAM API — state queries
    // -----------------------------------------------------------------------
    //
    // Returns the entity on success, or std::nullopt when the entity does not
    // exist. Throws (or propagates the SDK error) on an unrecoverable API
    // failure. Use IsPolicyAttachedTo* / IsUserInGroup for boolean checks
    // that need to distinguish NOT_FOUND from FAILURE.

    [[nodiscard]] std::optional<Aws::IAM::Model::Group>  GetGroup (const Aws::String& groupName)  const;
    [[nodiscard]] std::optional<Aws::IAM::Model::Policy> GetPolicy(const Aws::String& policyName) const;
    [[nodiscard]] std::optional<Aws::IAM::Model::Role>   GetRole  (const Aws::String& roleName)   const;
    [[nodiscard]] std::optional<Aws::IAM::Model::User>   GetUser  (const Aws::String& userName)   const;

    // -----------------------------------------------------------------------
    // Simple IAM API — creation
    // -----------------------------------------------------------------------

    [[nodiscard]] bool CreateGroup (const Aws::String& groupName,  Aws::IAM::Model::Group&  outGroupData);
    [[nodiscard]] bool CreatePolicy(const Aws::String& policyName, const Aws::String& policyDocument, Aws::IAM::Model::Policy& outPolicyData);
    [[nodiscard]] bool CreateRole  (const Aws::String& roleName,   const Aws::String& assumedPolicyDocument, Aws::IAM::Model::Role& outRoleData);
    [[nodiscard]] bool CreateUser  (const Aws::String& userName,   Aws::IAM::Model::User&   outUserData);

    // -----------------------------------------------------------------------
    // Simple IAM API — policy–principal relations
    // -----------------------------------------------------------------------

    [[nodiscard]] bool AttachPolicyToGroup(const Aws::String& policyArn, const Aws::String& groupName);
    [[nodiscard]] bool AttachPolicyToRole (const Aws::String& policyArn, const Aws::String& roleName);
    [[nodiscard]] bool AttachPolicyToUser (const Aws::String& policyArn, const Aws::String& userName);

    [[nodiscard]] bool DetachPolicyFromGroup(const Aws::String& policyArn, const Aws::String& groupName);
    [[nodiscard]] bool DetachPolicyFromRole (const Aws::String& policyArn, const Aws::String& roleName);
    [[nodiscard]] bool DetachPolicyFromUser (const Aws::String& policyArn, const Aws::String& userName);

    [[nodiscard]] QueryResult IsPolicyAttachedToGroup(const Aws::String& policyName, const Aws::String& groupName) const;
    [[nodiscard]] QueryResult IsPolicyAttachedToRole (const Aws::String& policyName, const Aws::String& roleName)  const;
    [[nodiscard]] QueryResult IsPolicyAttachedToUser (const Aws::String& policyName, const Aws::String& userName)  const;

    // -----------------------------------------------------------------------
    // Simple IAM API — user–group relations
    // -----------------------------------------------------------------------

    [[nodiscard]] QueryResult IsUserInGroup      (const Aws::String& userName, const Aws::String& groupName) const;
    [[nodiscard]] bool        AddUserToGroup     (const Aws::String& userName, const Aws::String& groupName);
    [[nodiscard]] bool        RemoveUserFromGroup(const Aws::String& userName, const Aws::String& groupName);

    // -----------------------------------------------------------------------
    // Simple IAM API — deletion
    // -----------------------------------------------------------------------

    [[nodiscard]] bool DeleteGroup (const Aws::String& groupName);
    [[nodiscard]] bool DeletePolicy(const Aws::String& policyName);
    [[nodiscard]] bool DeleteRole  (const Aws::String& roleName);
    [[nodiscard]] bool DeleteUser  (const Aws::String& userName);

    // -----------------------------------------------------------------------
    // Credentials file helpers
    // -----------------------------------------------------------------------

    [[nodiscard]] bool DoesCredentialsFileExist    (const Aws::String& credentialsFilename) const;
    [[nodiscard]] bool CreateCredentialsFileForUser(const Aws::String& credentialsFilename, const Aws::String& userName);

    // -----------------------------------------------------------------------
    // Cognito integration
    // -----------------------------------------------------------------------

    [[nodiscard]] QueryResult GetIdentityPool   (const Aws::String& poolName, Aws::String& outIdentityPoolId) const;
    [[nodiscard]] bool        CreateIdentityPool(const Aws::String& poolName, bool allowUnauthenticatedIdentities, Aws::String& outIdentityPoolId);
    [[nodiscard]] bool        DeleteIdentityPool(const Aws::String& poolName);

    [[nodiscard]] QueryResult IsRoleBoundToIdentityPool(const Aws::String& identityPoolId, const Aws::String& roleArn, IdentityPoolRoleBindingType roleKey) const;
    [[nodiscard]] bool        BindRoleToIdentityPool   (const Aws::String& identityPoolId, const Aws::String& roleArn, IdentityPoolRoleBindingType roleKey);

private:

    // -- Group teardown helpers --
    bool RemoveUsersFromGroup         (const Aws::String& groupName);
    bool DetachPoliciesFromGroup      (const Aws::String& groupName);
    bool DeleteInlinePoliciesFromGroup(const Aws::String& groupName);

    // -- User teardown helpers --
    bool DeleteAccessKeysForUser     (const Aws::String& userName);
    bool RemoveUserFromGroups        (const Aws::String& userName);
    bool RemoveCertificatesFromUser  (const Aws::String& userName);
    bool RemovePasswordFromUser      (const Aws::String& userName);
    bool DeleteInlinePoliciesFromUser(const Aws::String& userName);
    bool RemoveMFAFromUser           (const Aws::String& userName);
    bool DetachPoliciesFromUser      (const Aws::String& userName);

    // -- Policy teardown helpers --
    bool RemovePolicyFromEntities(const Aws::String& policyArn);

    // -- Role teardown helpers --
    bool RemoveRoleFromInstanceProfiles(const Aws::String& roleName);
    bool DeleteInlinePoliciesFromRole  (const Aws::String& roleName);
    bool DetachPoliciesFromRole        (const Aws::String& roleName);

    std::shared_ptr<Aws::IAM::IAMClient>                         m_iamClient;
    std::shared_ptr<Aws::CognitoIdentity::CognitoIdentityClient> m_cognitoClient;
};

} // namespace AccessManagement
} // namespace Aws
