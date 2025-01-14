// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.PowerShell.Cmdlets.MachineLearningServices.Models.Api20240401
{
    using static Microsoft.Azure.PowerShell.Cmdlets.MachineLearningServices.Runtime.Extensions;

    /// <summary>A paginated list of Datastore entities.</summary>
    public partial class DatastoreResourceArmPaginatedResult :
        Microsoft.Azure.PowerShell.Cmdlets.MachineLearningServices.Models.Api20240401.IDatastoreResourceArmPaginatedResult,
        Microsoft.Azure.PowerShell.Cmdlets.MachineLearningServices.Models.Api20240401.IDatastoreResourceArmPaginatedResultInternal
    {

        /// <summary>Backing field for <see cref="NextLink" /> property.</summary>
        private string _nextLink;

        /// <summary>
        /// The link to the next page of Datastore objects. If null, there are no additional pages.
        /// </summary>
        [Microsoft.Azure.PowerShell.Cmdlets.MachineLearningServices.Origin(Microsoft.Azure.PowerShell.Cmdlets.MachineLearningServices.PropertyOrigin.Owned)]
        public string NextLink { get => this._nextLink; set => this._nextLink = value; }

        /// <summary>Backing field for <see cref="Value" /> property.</summary>
        private Microsoft.Azure.PowerShell.Cmdlets.MachineLearningServices.Models.Api20240401.IDatastore[] _value;

        /// <summary>An array of objects of type Datastore.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.MachineLearningServices.Origin(Microsoft.Azure.PowerShell.Cmdlets.MachineLearningServices.PropertyOrigin.Owned)]
        public Microsoft.Azure.PowerShell.Cmdlets.MachineLearningServices.Models.Api20240401.IDatastore[] Value { get => this._value; set => this._value = value; }

        /// <summary>Creates an new <see cref="DatastoreResourceArmPaginatedResult" /> instance.</summary>
        public DatastoreResourceArmPaginatedResult()
        {

        }
    }
    /// A paginated list of Datastore entities.
    public partial interface IDatastoreResourceArmPaginatedResult :
        Microsoft.Azure.PowerShell.Cmdlets.MachineLearningServices.Runtime.IJsonSerializable
    {
        /// <summary>
        /// The link to the next page of Datastore objects. If null, there are no additional pages.
        /// </summary>
        [Microsoft.Azure.PowerShell.Cmdlets.MachineLearningServices.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"The link to the next page of Datastore objects. If null, there are no additional pages.",
        SerializedName = @"nextLink",
        PossibleTypes = new [] { typeof(string) })]
        string NextLink { get; set; }
        /// <summary>An array of objects of type Datastore.</summary>
        [Microsoft.Azure.PowerShell.Cmdlets.MachineLearningServices.Runtime.Info(
        Required = false,
        ReadOnly = false,
        Description = @"An array of objects of type Datastore.",
        SerializedName = @"value",
        PossibleTypes = new [] { typeof(Microsoft.Azure.PowerShell.Cmdlets.MachineLearningServices.Models.Api20240401.IDatastore) })]
        Microsoft.Azure.PowerShell.Cmdlets.MachineLearningServices.Models.Api20240401.IDatastore[] Value { get; set; }

    }
    /// A paginated list of Datastore entities.
    internal partial interface IDatastoreResourceArmPaginatedResultInternal

    {
        /// <summary>
        /// The link to the next page of Datastore objects. If null, there are no additional pages.
        /// </summary>
        string NextLink { get; set; }
        /// <summary>An array of objects of type Datastore.</summary>
        Microsoft.Azure.PowerShell.Cmdlets.MachineLearningServices.Models.Api20240401.IDatastore[] Value { get; set; }

    }
}