/*
Copyright 2022 The KCP Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package apiimporter

import (
	kcpclient "github.com/kcp-dev/kcp/pkg/client/clientset/versioned"
	apiresourceinformer "github.com/kcp-dev/kcp/pkg/client/informers/externalversions/apiresource/v1alpha1"
	clusterinformer "github.com/kcp-dev/kcp/pkg/client/informers/externalversions/cluster/v1alpha1"
	clusterctl "github.com/kcp-dev/kcp/pkg/reconciler/cluster"
)

func NewController(
	kcpClient kcpclient.Interface,
	clusterInformer clusterinformer.ClusterInformer,
	apiResourceImportInformer apiresourceinformer.APIResourceImportInformer,
	resourcesToSync []string,
) (*clusterctl.ClusterReconciler, error) {

	am := &apiImporterManager{
		kcpClient:                kcpClient,
		resourcesToSync:          resourcesToSync,
		clusterIndexer:           clusterInformer.Informer().GetIndexer(),
		apiresourceImportIndexer: apiResourceImportInformer.Informer().GetIndexer(),
		apiImporters:             map[string]*APIImporter{},
	}

	return clusterctl.NewClusterReconciler(
		"kcp-api-importer",
		am,
		kcpClient,
		clusterInformer,
		apiResourceImportInformer,
	)
}