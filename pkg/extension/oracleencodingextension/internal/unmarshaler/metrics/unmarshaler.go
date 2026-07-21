// Copyright Splunk, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package metrics implements unmarshaling of OCI (Oracle Cloud
// Infrastructure) Monitoring metrics, published in JSONL format, into
// OpenTelemetry metrics.
package metrics // import "github.com/signalfx/splunk-otel-collector/pkg/extension/oracleencodingextension/internal/unmarshaler/metrics"

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	conventions "go.opentelemetry.io/otel/semconv/v1.40.0"
	"go.uber.org/zap"
)

// oracleCloudNamespaceKey and oracleCloudResourceGroupKey are not yet part of
// the OTel semantic conventions oracle_cloud.* registry, so they are defined here
const (
	oracleCloudCompartmentIDKey = "oracle_cloud.compartment_id"
	oracleCloudNamespaceKey     = "oracle_cloud.namespace"
	oracleCloudResourceGroupKey = "oracle_cloud.resource_group"

	// oracleCloudRealmKey is the OTel semantic convention key for the OCI
	// realm the resource's tenancy belongs to (e.g. "oc1", "oc2").
	// See https://opentelemetry.io/docs/specs/semconv/registry/attributes/oracle-cloud/
	oracleCloudRealmKey = "oracle_cloud.realm"

	// dimensionResourceID is the OCI Monitoring dimension holding the OCID of
	// the resource emitting the metric. It is additionally promoted to the
	// Resource as cloud.resource_id.
	dimensionResourceID = "resourceId"

	// ocidPrefix is the prefix of the first segment of every OCID, e.g.
	// "ocid1" for the current OCID version.
	// See https://docs.oracle.com/en-us/iaas/Content/General/Concepts/identifiers.htm
	ocidPrefix = "ocid"

	// ocidRealmSegmentIndex is the index, after splitting an OCID on ".", of
	// the realm segment: ocid1.<resource-type>.<realm>.<region>[.<future-use>].<unique-id>
	ocidRealmSegmentIndex = 2
)

// ScopeName is the instrumentation scope name set on metrics produced by
// this unmarshaler.
const ScopeName = "github.com/signalfx/splunk-otel-collector/pkg/extension/oracleencodingextension"

// ociMetricRecord represents a single OCI Monitoring metric record, one of
// which is expected per line of JSONL input.
type ociMetricRecord struct {
	Namespace     string               `json:"namespace"`
	CompartmentID string               `json:"compartmentId"`
	ResourceGroup string               `json:"resourceGroup"`
	Name          string               `json:"name"`
	Dimensions    map[string]any       `json:"dimensions"`
	Metadata      ociMetricMetadata    `json:"metadata"`
	Datapoints    []ociMetricDatapoint `json:"datapoints"`
}

type ociMetricMetadata struct {
	Unit        string `json:"unit"`
	DisplayName string `json:"displayName"`
}

type ociMetricDatapoint struct {
	// Timestamp is reported by OCI Monitoring as epoch milliseconds.
	Timestamp int64   `json:"timestamp"`
	Value     float64 `json:"value"`
}

// ResourceMetricsUnmarshaler unmarshals OCI Monitoring metrics, encoded as
// JSONL, into pmetric.Metrics.
type ResourceMetricsUnmarshaler struct {
	logger *zap.Logger
}

// NewResourceMetricsUnmarshaler creates a new ResourceMetricsUnmarshaler.
func NewResourceMetricsUnmarshaler(logger *zap.Logger) ResourceMetricsUnmarshaler {
	return ResourceMetricsUnmarshaler{logger: logger}
}

// UnmarshalMetrics reads a JSONL-encoded payload of OCI metric records, one
// per line, and converts it into an OpenTelemetry pmetric.Metrics object.
func (r ResourceMetricsUnmarshaler) UnmarshalMetrics(buf []byte) (pmetric.Metrics, error) {
	allResourceMetrics := map[string]pmetric.ResourceMetrics{}

	reader := bufio.NewReader(bytes.NewReader(buf))
	for {
		line, err := reader.ReadBytes('\n')
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) > 0 {
			r.unmarshalRecord(allResourceMetrics, trimmed)
		}
		if err != nil {
			if err != io.EOF {
				return pmetric.NewMetrics(), fmt.Errorf("failed to read JSONL input: %w", err)
			}
			break
		}
	}

	md := pmetric.NewMetrics()
	for _, rm := range allResourceMetrics {
		rm.MoveTo(md.ResourceMetrics().AppendEmpty())
	}

	return md, nil
}

// Records sharing the same compartment, namespace, resource group and
// resource ID are grouped into a single ResourceMetrics.
func (r ResourceMetricsUnmarshaler) unmarshalRecord(
	allResourceMetrics map[string]pmetric.ResourceMetrics,
	jsonRecord []byte,
) {
	rec, err := r.getValidRecord(jsonRecord)
	if err != nil {
		r.logger.Warn("Skipping invalid OCI metric record", zap.Error(err))
		return
	}

	dataPoints := r.getDatapoints(rec)

	if dataPoints.Len() == 0 {
		r.logger.Warn("Skipping OCI metric record without valid datapoints",
			zap.Any("name", rec.Name),
			zap.Any("namespace", rec.Namespace),
			zap.Any("datapoints", rec.Datapoints))
		return
	}

	resourceID := extractResourceID(rec.Dimensions)
	resourceKey := rec.CompartmentID + "|" + rec.Namespace + "|" + rec.ResourceGroup + "|" + resourceID

	rm, found := allResourceMetrics[resourceKey]
	if !found {
		rm = pmetric.NewResourceMetrics()
		for k, v := range resourceAttributes(*rec, resourceID) {
			rm.Resource().Attributes().PutStr(k, v)
		}
		rm.ScopeMetrics().AppendEmpty().Scope().SetName(ScopeName)
		allResourceMetrics[resourceKey] = rm
	}

	scopeMetrics := rm.ScopeMetrics().At(0)
	m := scopeMetrics.Metrics().AppendEmpty()
	m.SetName(rec.Name)
	if rec.Metadata.Unit != "" {
		m.SetUnit(rec.Metadata.Unit)
	}
	if rec.Metadata.DisplayName != "" {
		m.SetDescription(rec.Metadata.DisplayName)
	}

	// OCI Monitoring does not report an explicit metric type, and
	// metadata.unit is descriptive (e.g. "ms") so always use gauge.
	dataPoints.MoveAndAppendTo(m.SetEmptyGauge().DataPoints())
}

func (r ResourceMetricsUnmarshaler) getValidRecord(jsonRecord []byte) (*ociMetricRecord, error) {
	var rec ociMetricRecord
	if err := json.Unmarshal(jsonRecord, &rec); err != nil {
		return nil, fmt.Errorf("JSON unmarshal failed for OCI metric record: %w", err)
	}

	if rec.Name == "" {
		return nil, fmt.Errorf(
			"no name set on OCI metric record (namespace=%q, compartmentId=%q)",
			rec.Namespace, rec.CompartmentID,
		)
	}

	return &rec, nil
}

func (r ResourceMetricsUnmarshaler) getDatapoints(rec *ociMetricRecord) pmetric.NumberDataPointSlice {
	dataPoints := pmetric.NewNumberDataPointSlice()
	for _, point := range rec.Datapoints {
		timestamp := time.UnixMilli(point.Timestamp)

		dp := dataPoints.AppendEmpty()
		dp.SetTimestamp(pcommon.NewTimestampFromTime(timestamp))
		dp.SetDoubleValue(point.Value)
		if len(rec.Dimensions) > 0 {
			if err := dp.Attributes().FromRaw(rec.Dimensions); err != nil {
				r.logger.Warn(
					"Failed to set attributes from dimensions",
					zap.Any("dimensions", rec.Dimensions),
					zap.Error(err),
				)
			}
		}
	}
	return dataPoints
}

// resourceAttributes maps an OCI metric record onto OpenTelemetry resource
// attributes, following the cloud.* semantic conventions plus the
// oracle_cloud.* namespace for fields with no generic equivalent.
func resourceAttributes(rec ociMetricRecord, resourceID string) map[string]string {
	attrs := map[string]string{
		string(conventions.CloudProviderKey): conventions.CloudProviderOracleCloud.Value.AsString(),
	}
	if rec.CompartmentID != "" {
		attrs[oracleCloudCompartmentIDKey] = rec.CompartmentID
	}
	if resourceID != "" {
		attrs[string(conventions.CloudResourceIDKey)] = resourceID
	}
	if rec.Namespace != "" {
		attrs[oracleCloudNamespaceKey] = rec.Namespace
	}
	if rec.ResourceGroup != "" {
		attrs[oracleCloudResourceGroupKey] = rec.ResourceGroup
	}
	if realm := extractRealm(rec.CompartmentID); realm != "" {
		attrs[oracleCloudRealmKey] = realm
	}
	return attrs
}

// extractRealm parses the realm segment out of an OCID, e.g. "oc1" out of
// "ocid1.compartment.oc1..exampleuniqueID".
// See https://docs.oracle.com/en-us/iaas/Content/General/Concepts/identifiers.htm
func extractRealm(ocid string) string {
	segments := strings.Split(ocid, ".")
	if len(segments) <= ocidRealmSegmentIndex || !strings.HasPrefix(segments[0], ocidPrefix) {
		return ""
	}
	return segments[ocidRealmSegmentIndex]
}

// extractResourceID reads the resourceId dimension out of an OCI metric
// record's dimensions, since it identifies the monitored resource itself and
// is promoted onto the Resource as cloud.resource_id. It is also kept in the
// returned dimensions so it remains available as a per-datapoint attribute.
// OCI Monitoring has been observed emitting this dimension key as either
// "resourceId" or "resourceID", so the key is matched case-insensitively.
func extractResourceID(dimensions map[string]any) (resourceID string) {
	if len(dimensions) == 0 {
		return ""
	}

	for k, v := range dimensions {
		if resourceID == "" && strings.EqualFold(k, dimensionResourceID) {
			resourceID, _ = v.(string)
			break
		}
	}
	return resourceID
}
