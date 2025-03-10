// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.Management.ApiManagement.Models
{
    using System.Linq;

    /// <summary>
    /// Tenant access information update parameters.
    /// </summary>
    [Microsoft.Rest.Serialization.JsonTransformation]
    public partial class AccessInformationCreateParameters
    {
        /// <summary>
        /// Initializes a new instance of the AccessInformationCreateParameters class.
        /// </summary>
        public AccessInformationCreateParameters()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the AccessInformationCreateParameters class.
        /// </summary>

        /// <param name="principalId">Principal (User) Identifier.
        /// </param>

        /// <param name="primaryKey">Primary access key. This property will not be filled on &#39;GET&#39; operations!
        /// Use &#39;/listSecrets&#39; POST request to get the value.
        /// </param>

        /// <param name="secondaryKey">Secondary access key. This property will not be filled on &#39;GET&#39; operations!
        /// Use &#39;/listSecrets&#39; POST request to get the value.
        /// </param>

        /// <param name="enabled">Determines whether direct access is enabled.
        /// </param>
        public AccessInformationCreateParameters(string principalId = default(string), string primaryKey = default(string), string secondaryKey = default(string), bool? enabled = default(bool?))

        {
            this.PrincipalId = principalId;
            this.PrimaryKey = primaryKey;
            this.SecondaryKey = secondaryKey;
            this.Enabled = enabled;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();


        /// <summary>
        /// Gets or sets principal (User) Identifier.
        /// </summary>
        [Newtonsoft.Json.JsonProperty(PropertyName = "properties.principalId")]
        public string PrincipalId {get; set; }

        /// <summary>
        /// Gets or sets primary access key. This property will not be filled on &#39;GET&#39;
        /// operations! Use &#39;/listSecrets&#39; POST request to get the value.
        /// </summary>
        [Newtonsoft.Json.JsonProperty(PropertyName = "properties.primaryKey")]
        public string PrimaryKey {get; set; }

        /// <summary>
        /// Gets or sets secondary access key. This property will not be filled on
        /// &#39;GET&#39; operations! Use &#39;/listSecrets&#39; POST request to get the value.
        /// </summary>
        [Newtonsoft.Json.JsonProperty(PropertyName = "properties.secondaryKey")]
        public string SecondaryKey {get; set; }

        /// <summary>
        /// Gets or sets determines whether direct access is enabled.
        /// </summary>
        [Newtonsoft.Json.JsonProperty(PropertyName = "properties.enabled")]
        public bool? Enabled {get; set; }
    }
}