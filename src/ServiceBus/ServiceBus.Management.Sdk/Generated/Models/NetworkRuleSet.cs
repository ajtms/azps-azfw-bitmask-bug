// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

namespace Microsoft.Azure.Management.ServiceBus.Models
{
    using System.Linq;

    /// <summary>
    /// Description of NetworkRuleSet resource.
    /// </summary>
    [Microsoft.Rest.Serialization.JsonTransformation]
    public partial class NetworkRuleSet : ProxyResource
    {
        /// <summary>
        /// Initializes a new instance of the NetworkRuleSet class.
        /// </summary>
        public NetworkRuleSet()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the NetworkRuleSet class.
        /// </summary>

        /// <param name="id">Fully qualified resource ID for the resource. Ex -
        /// /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}
        /// </param>

        /// <param name="name">The name of the resource
        /// </param>

        /// <param name="type">The type of the resource. E.g. &#34;Microsoft.EventHub/Namespaces&#34; or
        /// &#34;Microsoft.EventHub/Namespaces/EventHubs&#34;
        /// </param>

        /// <param name="location">The geo-location where the resource lives
        /// </param>

        /// <param name="systemData">The system meta data relating to this resource.
        /// </param>

        /// <param name="defaultAction">Default Action for Network Rule Set
        /// Possible values include: &#39;Allow&#39;, &#39;Deny&#39;</param>

        /// <param name="trustedServiceAccessEnabled">Value that indicates whether Trusted Service Access is Enabled or not.
        /// </param>

        /// <param name="virtualNetworkRules">List VirtualNetwork Rules
        /// </param>

        /// <param name="ipRules">List of IpRules
        /// </param>

        /// <param name="publicNetworkAccess">This determines if traffic is allowed over public network. By default it is
        /// enabled.
        /// Possible values include: &#39;Enabled&#39;, &#39;Disabled&#39;</param>
        public NetworkRuleSet(string id = default(string), string name = default(string), string type = default(string), string location = default(string), SystemData systemData = default(SystemData), string defaultAction = default(string), bool? trustedServiceAccessEnabled = default(bool?), System.Collections.Generic.IList<NWRuleSetVirtualNetworkRules> virtualNetworkRules = default(System.Collections.Generic.IList<NWRuleSetVirtualNetworkRules>), System.Collections.Generic.IList<NWRuleSetIpRules> ipRules = default(System.Collections.Generic.IList<NWRuleSetIpRules>), string publicNetworkAccess = default(string))

        : base(id, name, type, location)
        {
            this.SystemData = systemData;
            this.DefaultAction = defaultAction;
            this.TrustedServiceAccessEnabled = trustedServiceAccessEnabled;
            this.VirtualNetworkRules = virtualNetworkRules;
            this.IPRules = ipRules;
            this.PublicNetworkAccess = publicNetworkAccess;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();


        /// <summary>
        /// Gets the system meta data relating to this resource.
        /// </summary>
        [Newtonsoft.Json.JsonProperty(PropertyName = "systemData")]
        public SystemData SystemData {get; private set; }

        /// <summary>
        /// Gets or sets default Action for Network Rule Set Possible values include: &#39;Allow&#39;, &#39;Deny&#39;
        /// </summary>
        [Newtonsoft.Json.JsonProperty(PropertyName = "properties.defaultAction")]
        public string DefaultAction {get; set; }

        /// <summary>
        /// Gets or sets value that indicates whether Trusted Service Access is Enabled
        /// or not.
        /// </summary>
        [Newtonsoft.Json.JsonProperty(PropertyName = "properties.trustedServiceAccessEnabled")]
        public bool? TrustedServiceAccessEnabled {get; set; }

        /// <summary>
        /// Gets or sets list VirtualNetwork Rules
        /// </summary>
        [Newtonsoft.Json.JsonProperty(PropertyName = "properties.virtualNetworkRules")]
        public System.Collections.Generic.IList<NWRuleSetVirtualNetworkRules> VirtualNetworkRules {get; set; }

        /// <summary>
        /// Gets or sets list of IpRules
        /// </summary>
        [Newtonsoft.Json.JsonProperty(PropertyName = "properties.ipRules")]
        public System.Collections.Generic.IList<NWRuleSetIpRules> IPRules {get; set; }

        /// <summary>
        /// Gets or sets this determines if traffic is allowed over public network. By
        /// default it is enabled. Possible values include: &#39;Enabled&#39;, &#39;Disabled&#39;
        /// </summary>
        [Newtonsoft.Json.JsonProperty(PropertyName = "properties.publicNetworkAccess")]
        public string PublicNetworkAccess {get; set; }
    }
}