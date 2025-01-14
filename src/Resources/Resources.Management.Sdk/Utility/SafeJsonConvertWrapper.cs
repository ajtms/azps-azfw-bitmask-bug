﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//
// This is a wrapper class for Microsoft.Rest.Serialization.SafeJsonConvert. We create this class to support string values to
// Deployment.Properties.Template and Deployment.Properties.Parameters. The string values must be valid JSON payloads for tempalte
// and parameters respectively. 
//

namespace Microsoft.Azure.Management.Resources.Utility
{
    using Microsoft.Azure.Management.Resources.Models;
    using Microsoft.Rest;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;

    public static class SafeJsonConvertWrapper
    {
        public static string SerializeDeployment(Deployment deployment, JsonSerializerSettings settings)
        {
            CheckSerializationForDeploymentProperties(deployment.Properties);

            return Rest.Serialization.SafeJsonConvert.SerializeObject(deployment, settings);
        }

        public static string SerializeScopeDeployment(ScopedDeployment deployment, JsonSerializerSettings settings)
        {
            CheckSerializationForDeploymentProperties(deployment.Properties);

            return Rest.Serialization.SafeJsonConvert.SerializeObject(deployment, settings);
        }

        public static string SerializeDeploymentWhatIf(DeploymentWhatIf deploymentWhatIf, JsonSerializerSettings settings)
        {
            CheckSerializationForDeploymentProperties(deploymentWhatIf.Properties);

            return Rest.Serialization.SafeJsonConvert.SerializeObject(deploymentWhatIf, settings);
        }

        public static string SerializeScopedDeploymentWhatIf(ScopedDeploymentWhatIf deploymentWhatIf, JsonSerializerSettings settings)
        {
            CheckSerializationForDeploymentProperties(deploymentWhatIf.Properties);

            return Rest.Serialization.SafeJsonConvert.SerializeObject(deploymentWhatIf, settings);
        }

        public static void CheckSerializationForDeploymentProperties(DeploymentProperties properties)
        {
            if (properties != null)
            {
                if (properties.Template is string templateContent)
                {
                    try
                    {
                        properties.Template = JObject.Parse(templateContent);
                    }
                    catch (JsonException ex)
                    {
                        throw new SerializationException("Unable to serialize template.", ex);
                    }
                }
            }
        }
    }
}
