// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.Management.DataMigration.Models
{
    using System.Linq;

    /// <summary>
    /// Output for command that completes online migration for an Azure SQL
    /// Database Managed Instance.
    /// </summary>
    public partial class MigrateMISyncCompleteCommandOutput
    {
        /// <summary>
        /// Initializes a new instance of the MigrateMISyncCompleteCommandOutput class.
        /// </summary>
        public MigrateMISyncCompleteCommandOutput()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the MigrateMISyncCompleteCommandOutput class.
        /// </summary>

        /// <param name="errors">List of errors that happened during the command execution
        /// </param>
        public MigrateMISyncCompleteCommandOutput(System.Collections.Generic.IList<ReportableException> errors = default(System.Collections.Generic.IList<ReportableException>))

        {
            this.Errors = errors;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();


        /// <summary>
        /// Gets or sets list of errors that happened during the command execution
        /// </summary>
        [Newtonsoft.Json.JsonProperty(PropertyName = "errors")]
        public System.Collections.Generic.IList<ReportableException> Errors {get; set; }
    }
}