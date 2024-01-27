//
// Copyright (c) Microsoft.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Net;
using Microsoft.Azure.Commands.Common.Compute.Version2016_04_preview.Models;
using Microsoft.Azure.Management.WebSites.Version2016_09_01.Models;
using Microsoft.Rest;
using Newtonsoft.Json;

namespace Microsoft.Azure.Commands.Network.Models
{
    public class PSAzureFirewall : PSTopLevelResource
    {
        private const string AzureFirewallSubnetName = "AzureFirewallSubnet";
        private const string AzureFirewallMgmtSubnetName = "AzureFirewallManagementSubnet";
        private const string AzureFirewallMgmtIpConfigurationName = "AzureFirewallMgmtIpConfiguration";
        private const string AzureFirewallIpConfigurationName = "AzureFirewallIpConfiguration";
        private const string IANAPrivateRanges = "IANAPrivateRanges";

        private string[] privateRange;

        public List<PSAzureFirewallIpConfiguration> IpConfigurations { get; set; }

        public PSAzureFirewallIpConfiguration ManagementIpConfiguration { get; set; }

        public List<PSAzureFirewallApplicationRuleCollection> ApplicationRuleCollections { get; set; }

        public List<PSAzureFirewallNatRuleCollection> NatRuleCollections { get; set; }

        public List<PSAzureFirewallNetworkRuleCollection> NetworkRuleCollections { get; set; }

        public PSAzureFirewallSku Sku { get; set; }

        public Microsoft.Azure.Management.Network.Models.SubResource VirtualHub { get; set; }

        public Microsoft.Azure.Management.Network.Models.SubResource FirewallPolicy { get; set; }

        public string ThreatIntelMode { get; set; }

        public PSAzureFirewallThreatIntelWhitelist ThreatIntelWhitelist { get; set; }

        public PSAzureFirewallHubIpAddresses HubIPAddresses { get; set; }

        public PSAzureFirewallIpPrefix LearnedIPPrefixes { get; set; }

        public string[] PrivateRange
        {
            get
            {
                return this.privateRange;
            }
            set
            {
                if (value != null)
                {
                    ValidatePrivateRange(value);
                    privateRange = value;
                }
            }
        }

        public string DNSEnableProxy { get; set; }

        public string[] DNSServer { get; set; }

        public string ProvisioningState { get; set; }

        public List<string> Zones { get; set; }

        public string AllowActiveFTP { get; set; }

        public string EnableFatFlowLogging { get; set; }

        public string EnableUDPLogOptimization { get; set; }

        public string RouteServerId { get; set; }

        [JsonIgnore]
        public string IpConfigurationsText
        {
            get { return JsonConvert.SerializeObject(IpConfigurations, Formatting.Indented, new JsonSerializerSettings() { NullValueHandling = NullValueHandling.Ignore }); }
        }

        [JsonIgnore]
        public string ManagementIpConfigurationText
        {
            get { return JsonConvert.SerializeObject(ManagementIpConfiguration, Formatting.Indented, new JsonSerializerSettings() { NullValueHandling = NullValueHandling.Ignore }); }
        }

        [JsonIgnore]
        public string ApplicationRuleCollectionsText
        {
            get { return JsonConvert.SerializeObject(ApplicationRuleCollections, Formatting.Indented); }
        }

        [JsonIgnore]
        public string NatRuleCollectionsText
        {
            get { return JsonConvert.SerializeObject(NatRuleCollections, Formatting.Indented); }
        }

        [JsonIgnore]
        public string NetworkRuleCollectionsText
        {
            get { return JsonConvert.SerializeObject(NetworkRuleCollections, Formatting.Indented); }
        }

        [JsonIgnore]
        public string ThreatIntelWhitelistText
        {
            get { return JsonConvert.SerializeObject(ThreatIntelWhitelist, Formatting.Indented); }
        }


        [JsonIgnore]
        public string PrivateRangeText
        {
            get { return JsonConvert.SerializeObject(PrivateRange, Formatting.Indented); }
        }

        [JsonIgnore]
        public string DNSServersText
        {
            get { return JsonConvert.SerializeObject(DNSServer, Formatting.Indented); }
        }

        #region Ip Configuration Operations
        public void Allocate(Management.Network.Models.SubResource virtualHub)
        {
            if (this.Sku.Name.Equals("AZFW_Hub", StringComparison.OrdinalIgnoreCase))
            {
                this.VirtualHub = virtualHub;
            }
            else
            {
                throw new ArgumentException($"Hub firewall allocation attempted on a Non-hub firewall. Firewall name = {this.Name}, Sku name = {this.Sku.Name}");
            }
        }

        public void Allocate(PSVirtualNetwork virtualNetwork, PSPublicIpAddress[] publicIpAddresses, PSPublicIpAddress ManagementPublicIpAddress = null)
        {
            if (virtualNetwork == null)
            {
                throw new ArgumentNullException(nameof(virtualNetwork), "Virtual Network cannot be null!");
            }

            if (ManagementPublicIpAddress == null)
            {
                if (publicIpAddresses == null || publicIpAddresses.Count() == 0)
                {
                    throw new ArgumentNullException(nameof(publicIpAddresses), "Public IP Addresses cannot be null or empty!");
                }
            }

            PSSubnet firewallSubnet = null;
            try
            {
                firewallSubnet = virtualNetwork.Subnets.Single(subnet => AzureFirewallSubnetName.Equals(subnet.Name));
            }
            catch (InvalidOperationException)
            {
                throw new ArgumentException($"Virtual Network {virtualNetwork.Name} should contain a Subnet named {AzureFirewallSubnetName}");
            }

            PSSubnet firewallMgmtSubnet = null;
            if (ManagementPublicIpAddress != null)
            {
                try
                {
                    firewallMgmtSubnet = virtualNetwork.Subnets.Single(subnet => AzureFirewallMgmtSubnetName.Equals(subnet.Name));
                }
                catch (InvalidOperationException)
                {
                    throw new ArgumentException($"Virtual Network {virtualNetwork.Name} should contain a Subnet named {AzureFirewallMgmtSubnetName}");
                }

                this.ManagementIpConfiguration = new PSAzureFirewallIpConfiguration
                {
                    Name = AzureFirewallMgmtIpConfigurationName,
                    PublicIpAddress = new PSResourceId { Id = ManagementPublicIpAddress.Id },
                    Subnet = new PSResourceId { Id = firewallMgmtSubnet.Id }
                };
            }

            this.IpConfigurations = new List<PSAzureFirewallIpConfiguration>();

            if (publicIpAddresses != null && publicIpAddresses.Count() > 0)
            {
                for (var i = 0; i < publicIpAddresses.Count(); i++)
                {
                    this.IpConfigurations.Add(
                        new PSAzureFirewallIpConfiguration
                        {
                            Name = $"{AzureFirewallIpConfigurationName}{i}",
                            PublicIpAddress = new PSResourceId { Id = publicIpAddresses[i].Id }
                        });
                }
            }
            else
            {
                this.IpConfigurations.Add(new PSAzureFirewallIpConfiguration { Name = $"{AzureFirewallIpConfigurationName}{0}" });
            }

            this.IpConfigurations[0].Subnet = new PSResourceId { Id = firewallSubnet.Id };
        }
        public void AllocateBasicSku(PSVirtualNetwork virtualNetwork, PSPublicIpAddress[] publicIpAddresses, PSPublicIpAddress ManagementPublicIpAddress)
        {
            if (virtualNetwork == null)
            {
                throw new ArgumentNullException(nameof(virtualNetwork), "Virtual Network cannot be null!");
            }

            if (ManagementPublicIpAddress == null)
            {
                throw new ArgumentNullException(nameof(ManagementPublicIpAddress), "ManagementPublicIpAddress is required for Azure Firewalls with Basic SKU!");
            }

            PSSubnet firewallMgmtSubnet = null;
            try
            {
                firewallMgmtSubnet = virtualNetwork.Subnets.Single(subnet => AzureFirewallMgmtSubnetName.Equals(subnet.Name));
            }
            catch (InvalidOperationException)
            {
                throw new ArgumentException($"Virtual Network {virtualNetwork.Name} should contain a Subnet named {AzureFirewallMgmtSubnetName}");
            }

            PSSubnet firewallSubnet = null;
            try
            {
                firewallSubnet = virtualNetwork.Subnets.Single(subnet => AzureFirewallSubnetName.Equals(subnet.Name));
            }
            catch (InvalidOperationException)
            {
                throw new ArgumentException($"Virtual Network {virtualNetwork.Name} should contain a Subnet named {AzureFirewallSubnetName}");
            }

            this.ManagementIpConfiguration = new PSAzureFirewallIpConfiguration
            {
                Name = AzureFirewallMgmtIpConfigurationName,
                PublicIpAddress = new PSResourceId { Id = ManagementPublicIpAddress.Id },
                Subnet = new PSResourceId { Id = firewallMgmtSubnet.Id }
            };

            this.IpConfigurations = new List<PSAzureFirewallIpConfiguration>();

            if (publicIpAddresses != null && publicIpAddresses.Count() > 0)
            {
                for (var i = 0; i < publicIpAddresses.Count(); i++)
                {
                    this.IpConfigurations.Add(
                        new PSAzureFirewallIpConfiguration
                        {
                            Name = $"{AzureFirewallIpConfigurationName}{i}",
                            PublicIpAddress = new PSResourceId { Id = publicIpAddresses[i].Id }
                        });
                }
            }
            else
            {
                this.IpConfigurations.Add(new PSAzureFirewallIpConfiguration { Name = $"{AzureFirewallIpConfigurationName}{0}" });
            }

            this.IpConfigurations[0].Subnet = new PSResourceId { Id = firewallSubnet.Id };
        }
        public void Deallocate()
        {
            if (this.Sku.Name.Equals("AZFW_Hub", StringComparison.OrdinalIgnoreCase))
            {
                this.VirtualHub = null;
            }
            else
            {
                this.IpConfigurations = new List<PSAzureFirewallIpConfiguration>();
                this.ManagementIpConfiguration = null;
            }
        }

        public void AddPublicIpAddress(PSPublicIpAddress publicIpAddress)
        {
            if (publicIpAddress == null)
            {
                throw new ArgumentNullException(nameof(publicIpAddress), "Public IP Address cannot be null!");
            }

            PSAzureFirewallIpConfiguration conflictingIpConfig = null;

            if (this.IpConfigurations.Count > 0)
            {
                conflictingIpConfig = this.IpConfigurations.SingleOrDefault
                    (ipConfig => string.Equals(ipConfig.PublicIpAddress?.Id, publicIpAddress.Id, System.StringComparison.CurrentCultureIgnoreCase));

                if (conflictingIpConfig != null)
                {
                    throw new ArgumentException($"Public IP Address {publicIpAddress.Id} is already attached to firewall {this.Name}");
                }
            }
            else
            {
                throw new InvalidOperationException($"Please invoke {nameof(Allocate)} to attach the firewall to a Virtual Network");
            }

            PSAzureFirewallIpConfiguration configWithoutIP = this.IpConfigurations.SingleOrDefault
                    (ipConfig => (ipConfig.Subnet != null && ipConfig.PublicIpAddress == null));

            if (configWithoutIP != null)
            {
                configWithoutIP.PublicIpAddress = new PSResourceId { Id = publicIpAddress.Id };
            }
            else
            {
                var i = 0;
                conflictingIpConfig = null;
                var newIpConfigName = "";
                do
                {
                    newIpConfigName = $"{AzureFirewallIpConfigurationName}{this.IpConfigurations.Count + i}";
                    conflictingIpConfig = this.IpConfigurations.SingleOrDefault
                        (ipConfig => string.Equals(ipConfig.Name, newIpConfigName, System.StringComparison.CurrentCultureIgnoreCase));
                    i++;
                } while (conflictingIpConfig != null);

                this.IpConfigurations.Add(
                    new PSAzureFirewallIpConfiguration
                    {
                        Name = newIpConfigName,
                        PublicIpAddress = new PSResourceId { Id = publicIpAddress.Id }
                    });
            }
        }

        public void RemovePublicIpAddress(PSPublicIpAddress publicIpAddress)
        {
            if (publicIpAddress == null)
            {
                throw new ArgumentNullException(nameof(publicIpAddress), "Public IP Address cannot be null!");
            }

            var ipConfigToRemove = this.IpConfigurations.SingleOrDefault
                (ipConfig => string.Equals(ipConfig.PublicIpAddress?.Id, publicIpAddress.Id, System.StringComparison.CurrentCultureIgnoreCase));

            if (ipConfigToRemove == null)
            {
                throw new ArgumentException($"Public IP Address {publicIpAddress.Id} is not attached to firewall {this.Name}");
            }

            if (this.ManagementIpConfiguration != null) {
                if (ipConfigToRemove.Subnet != null)
                {
                    ipConfigToRemove.PublicIpAddress = null;
                }
                else
                {
                    this.IpConfigurations.Remove(ipConfigToRemove);
                }
            }
            else
            {
                if (this.IpConfigurations.Count > 1 && ipConfigToRemove.Subnet != null)
                {
                    throw new InvalidOperationException($"Cannot remove IpConfiguration {ipConfigToRemove.Name} because it references subnet {ipConfigToRemove.Subnet.Id}. Move the subnet reference to another IpConfiguration and try again.");
                }

                if (this.IpConfigurations.Count == 1)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"WARNING: Removing the last Public IP Address, this will deallocate the firewall. You will have to invoke {nameof(Allocate)} to reallocate it.");
                    Console.ResetColor();
                }

                this.IpConfigurations.Remove(ipConfigToRemove);
            }
        }

        #endregion // Ip Configuration Operations

        #region Application Rule Collections Operations

        public void AddApplicationRuleCollection(PSAzureFirewallApplicationRuleCollection ruleCollection)
        {
            this.ApplicationRuleCollections = AddRuleCollection(ruleCollection, this.ApplicationRuleCollections);
        }

        public PSAzureFirewallApplicationRuleCollection GetApplicationRuleCollectionByName(string ruleCollectionName)
        {
            return GetRuleCollectionByName(ruleCollectionName, this.ApplicationRuleCollections);
        }

        public PSAzureFirewallApplicationRuleCollection GetApplicationRuleCollectionByPriority(uint priority)
        {
            return this.ApplicationRuleCollections?.FirstOrDefault(rc => rc.Priority == priority);
        }

        public void RemoveApplicationRuleCollectionByName(string ruleCollectionName)
        {
            var ruleCollection = this.GetApplicationRuleCollectionByName(ruleCollectionName);
            this.ApplicationRuleCollections.Remove(ruleCollection);
        }

        public void RemoveApplicationRuleCollectionByPriority(uint priority)
        {
            var ruleCollection = this.GetApplicationRuleCollectionByPriority(priority);
            this.ApplicationRuleCollections.Remove(ruleCollection);
        }

        #endregion // Application Rule Collections Operations

        #region NAT Rule Collections Operations

        public void AddNatRuleCollection(PSAzureFirewallNatRuleCollection ruleCollection)
        {
            this.NatRuleCollections = AddRuleCollection(ruleCollection, this.NatRuleCollections);
        }

        public PSAzureFirewallNatRuleCollection GetNatRuleCollectionByName(string ruleCollectionName)
        {
            return GetRuleCollectionByName(ruleCollectionName, this.NatRuleCollections);
        }

        public PSAzureFirewallNatRuleCollection GetNatRuleCollectionByPriority(uint priority)
        {
            return this.NatRuleCollections?.FirstOrDefault(rc => rc.Priority == priority);
        }

        public void RemoveNatRuleCollectionByName(string ruleCollectionName)
        {
            var ruleCollection = this.GetNatRuleCollectionByName(ruleCollectionName);
            this.NatRuleCollections.Remove(ruleCollection);
        }

        public void RemoveNatRuleCollectionByPriority(uint priority)
        {
            var ruleCollection = this.GetNatRuleCollectionByPriority(priority);
            this.NatRuleCollections.Remove(ruleCollection);
        }

        #endregion // NAT Rule Collections Operations

        #region Network Rule Collections Operations

        public void AddNetworkRuleCollection(PSAzureFirewallNetworkRuleCollection ruleCollection)
        {
            this.NetworkRuleCollections = AddRuleCollection(ruleCollection, this.NetworkRuleCollections);
        }

        public PSAzureFirewallNetworkRuleCollection GetNetworkRuleCollectionByName(string ruleCollectionName)
        {
            return this.GetRuleCollectionByName(ruleCollectionName, this.NetworkRuleCollections);
        }

        public PSAzureFirewallNetworkRuleCollection GetNetworkRuleCollectionByPriority(uint priority)
        {
            return this.NetworkRuleCollections?.FirstOrDefault(rc => rc.Priority == priority);
        }

        public void RemoveNetworkRuleCollectionByName(string ruleCollectionName)
        {
            var ruleCollection = this.GetNetworkRuleCollectionByName(ruleCollectionName);
            this.NetworkRuleCollections?.Remove(ruleCollection);
        }

        public void RemoveNetworkRuleCollectionByPriority(uint priority)
        {
            var ruleCollection = this.GetNetworkRuleCollectionByPriority(priority);
            this.NetworkRuleCollections?.Remove(ruleCollection);
        }

        #endregion // Application Rule Collections Operations

        #region Private Range Validation
        private void ValidatePrivateRange(string[] privateRange)
        {
            foreach (var ip in privateRange)
            {
                if (ip.Equals(IANAPrivateRanges, StringComparison.OrdinalIgnoreCase))
                    continue;

                if (ip.Contains("/"))
                    ValidateMaskedIpAddress(ip);
                else
                    ValidateSingleIpAddress(ip);
            }
        }

        private void ValidateSingleIpAddress(string ipAddress)
        {
            IPAddress ipVal;
            if (!IPAddress.TryParse(ipAddress, out ipVal) || ipVal.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            {
                throw new PSArgumentException(String.Format("\'{0}\' is not a valid private range ip address", ipAddress));
            }
            else
            {
                Console.WriteLine($"Parsed to {ipVal}");
            }
        }

        private void ValidateMaskedIpAddressOLD(string ipAddress)
        {
            var split = ipAddress.Split('/');
            if (split.Length != 2)
                throw new PSArgumentException(String.Format("\'{0}\' is not a valid private range ip address", ipAddress));

            // validate the ip
            ValidateSingleIpAddress(split[0]);

            // validate mask
            var bit = 0;
            if (!Int32.TryParse(split[1], out bit) || bit < 0 || bit > 32)
                throw new PSArgumentException(String.Format("\'{0}\' is not a valid private range ip address, subnet mask should between 0 and 32", ipAddress));

            // validated that unmasked bits are 0
            var splittedIp = split[0].Split('.');
            var ip = Int32.Parse(splittedIp[0]) << 24;            
            ip += (Int32.Parse(splittedIp[1]) << 16) + (Int32.Parse(splittedIp[2]) << 8) + Int32.Parse(splittedIp[3]);
            // Still need to fix fully to prevent any /32 from passing
            if ((ip << bit != 0) && (bit != 32)) // left-shifting on an int/uint will only use the 5 least signficant digits, so a shift of 32 [0010 0000] will actually become a shift of 0
                throw new PSArgumentException(String.Format("\'{0}\' is not a valid private range ip address, bits not covered by subnet mask should be all 0", ipAddress));
        }

        private void ValidateMaskedIpAddress(string ipAddress)
        {
            ValidateIPv4CidrNotation(ipAddress);
        }

        private void ValidateIPv4CidrNotation(string ipv4Cidr)
        {
            Console.WriteLine("0");
            var subnet = ipv4Cidr.Split('/');
            if (subnet.Length != 2)
                throw new PSArgumentException(String.Format("\'{0}\' is not a valid private range ip address", ipv4Cidr));
            Console.WriteLine("1");
            uint address;
            if (!TryParseIPv4Address(subnet[0], out address))
            {
                throw new PSArgumentException(String.Format("\'{0}\' is not a valid private range ip address", ipv4Cidr));
            }
            Console.WriteLine($"Parsed '{subnet[0]}' into unit {address}");
            int host;
            if (!TryParseIPv4HostIdentifier(subnet[1], out host))
            {
                throw new PSArgumentException(String.Format("\'{0}\' is not a valid private range ip address, subnet mask should between 0 and 32", ipv4Cidr));
            }
            Console.WriteLine("3");
            
            if (!doesNetworkPrefixCorrectlyMaskHost(address, host))
            {
                uint recommendedAddressBits;
                if (TryApplyMask(address, host, out recommendedAddressBits))
                {
                    string recommendation = $"Try using '{uintToIPv4AddressString(recommendedAddressBits)}' instead.";
                    throw new PSArgumentException($"The network prefix for the CIDR string '{ipv4Cidr}' should be masked according to the suffix '{host}'. {recommendation}");
                }
                else
                {
                    throw new PSArgumentException($"The network prefix for the CIDR string '{ipv4Cidr}' should be masked according to the suffix '{host}'.");
                } 
            }

            Console.WriteLine("4");
        }

        private string uintToIPv4AddressString(uint address)
        {
            var bytes = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                bytes[i] = (byte) (address >> (8 * (3-i)));
            }

            return String.Join(".", bytes);
        }

        private void ValidateIPv4SubnetMask(string subnetMask)
        {
            int bit;
            if (!Int32.TryParse(subnetMask, out bit) || isValidHostIdentifier(bit))
                throw new PSArgumentException(String.Format("\'{0}\' is not a valid private range ip address, subnet mask should between 0 and 32", subnetMask));
        }

        private bool isValidHostIdentifier(int host)
        {
            return host >= 0 && host <= 32;
        }

        private bool isValidIPv4Block(int block)
        {
            return block >= 0 && block <= 255;
        }

        private bool doesNetworkPrefixCorrectlyMaskHost(uint networkPrefix, int hostIdentifier)
        {
            const uint fullMask = UInt32.MaxValue;
            Console.WriteLine($"networkPrefix: {networkPrefix}");
            Console.WriteLine($"hostIdentifier: {hostIdentifier}");
            Console.WriteLine($"After shift: {networkPrefix << hostIdentifier}");
            if (hostIdentifier > 32 || hostIdentifier < 0) return false;
            if (hostIdentifier == 32 && networkPrefix != fullMask) return false;
            if (hostIdentifier == 32 && networkPrefix == fullMask) return true;

            return (networkPrefix << hostIdentifier) == 0;
        }

        private bool TryApplyMask(uint address, int prefixLength, out uint maskedAddress)
        {
            maskedAddress = 0;
            if (!isValidHostIdentifier(prefixLength)) return false;
            int shift = (32 - prefixLength);
            maskedAddress = (address >> shift) << shift;

            return true;
        }

        private bool TryParseIPv4Address(string address, out uint parsed)
        {
            bool isValid = true;
            parsed = 0;
            var asStrings = address.Split('.');

            if (asStrings.Length != 4)
            {
                return false;
            }

            uint[] asBits = new uint[4];
            for (int i = 0; i < 4; i++)
            {
                uint bits = 0;
                if (TryParseIPv4Block(asStrings[i], out bits))
                {
                    asBits[i] = bits;
                }
                else
                {
                    isValid = false;
                }
            }

            for (int i = 0; i < 4; i++)
            {
                int amountToShift = (8 * (3 - i)); // 24, 16, 8, 0
                parsed += (asBits[i] << amountToShift);
            }

            return isValid;
        }

        private bool TryParseIPv4HostIdentifier(string host, out int parsed)
        {
            return Int32.TryParse(host, out parsed) && parsed >= 0 && parsed <= 32;
        }

        private bool TryParseIPv4Block(string block, out uint parsed)
        {
            return UInt32.TryParse(block, out parsed) && parsed >= 0 && parsed <= 255;
        }

        /// <summary>
        /// Validates the host identifier part of an IPv4 CIDR notation string
        /// </summary>
        /// <param name="host"></param>
        /// <exception cref="PSArgumentException"></exception>
        private void ValidateIPv4SubnetHostIdentifier(string host)
        {
            int bit;
            if (!Int32.TryParse(host, out bit) || bit < 0 || bit > 32)
                throw new PSArgumentException(String.Format("\'{0}\' is not a valid private range ip address, subnet mask should between 0 and 32", host));
        }

        #endregion

        #region DNS Proxy Validation

        public void ValidateDNSProxyRequirements()
        {
            if (string.Equals(this.DNSEnableProxy, "true", StringComparison.OrdinalIgnoreCase))
            {
                // Nothing to validate since they have enabled DNS Proxy
                return;
            }

            // Need to check if any Network Rules have FQDNs
            var netRuleCollections = this.NetworkRuleCollections?.Where(rc => rc?.Rules != null && rc.Rules.Any()).ToList();
            if (netRuleCollections == null)
            {
                // No network rules so nothing to do
                return;
            }

            foreach (var netRuleCollection in netRuleCollections)
            {
                foreach (var rule in netRuleCollection.Rules)
                {
                    if (rule?.DestinationFqdns != null && rule.DestinationFqdns.Any())
                    {
                        throw new PSArgumentException(string.Format("Found FQDNs {0} in network rule collection {1} rule {2} without DNS proxy being enabled or requirement setting disabled",
                            rule.DestinationFqdns, netRuleCollection.Name, rule.Name));
                    }
                }
            }
        }

        #endregion

        #region Private Methods

        private List<BaseRuleCollection> AddRuleCollection<BaseRuleCollection>(BaseRuleCollection ruleCollection, List<BaseRuleCollection> existingRuleCollections) where BaseRuleCollection : PSAzureFirewallBaseRuleCollection
        {
            if (existingRuleCollections == null)
            {
                existingRuleCollections = new List<BaseRuleCollection>();
            }

            existingRuleCollections.Add(ruleCollection);
            return existingRuleCollections;
        }

        private BaseRuleCollection GetRuleCollectionByName<BaseRuleCollection>(string ruleCollectionName, List<BaseRuleCollection> ruleCollections) where BaseRuleCollection : PSAzureFirewallBaseRuleCollection
        {
            if (string.IsNullOrEmpty(ruleCollectionName))
            {
                throw new ArgumentException($"Rule Collection name cannot be an empty string.");
            }

            var ruleCollection = ruleCollections?.FirstOrDefault(rc => ruleCollectionName.Equals(rc.Name));

            if (ruleCollection == null)
            {
                throw new ArgumentException($"Rule Collection with name {ruleCollectionName} does not exist.");
            }

            return ruleCollection;
        }
        #endregion // Private Methods
    }
}
