// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.Management.ApiManagement.Models
{
    using System.Linq;

    /// <summary>
    /// Policy contract Properties.
    /// </summary>
    public partial class PolicyContractProperties
    {
        /// <summary>
        /// Initializes a new instance of the PolicyContractProperties class.
        /// </summary>
        public PolicyContractProperties()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the PolicyContractProperties class.
        /// </summary>

        /// <param name="value">Contents of the Policy as defined by the format.
        /// </param>

        /// <param name="format">Format of the policyContent.
        /// Possible values include: &#39;xml&#39;, &#39;xml-link&#39;, &#39;rawxml&#39;, &#39;rawxml-link&#39;</param>
        public PolicyContractProperties(string value, string format = default(string))

        {
            this.Value = value;
            this.Format = format;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();


        /// <summary>
        /// Gets or sets contents of the Policy as defined by the format.
        /// </summary>
        [Newtonsoft.Json.JsonProperty(PropertyName = "value")]
        public string Value {get; set; }

        /// <summary>
        /// Gets or sets format of the policyContent. Possible values include: &#39;xml&#39;, &#39;xml-link&#39;, &#39;rawxml&#39;, &#39;rawxml-link&#39;
        /// </summary>
        [Newtonsoft.Json.JsonProperty(PropertyName = "format")]
        public string Format {get; set; }
        /// <summary>
        /// Validate the object.
        /// </summary>
        /// <exception cref="Microsoft.Rest.ValidationException">
        /// Thrown if validation fails
        /// </exception>
        public virtual void Validate()
        {
            if (this.Value == null)
            {
                throw new Microsoft.Rest.ValidationException(Microsoft.Rest.ValidationRules.CannotBeNull, "Value");
            }


        }
    }
}