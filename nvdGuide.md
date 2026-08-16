CVE API
The CVE API is used to easily retrieve information on a single CVE or a collection of CVE from the NVD. The NVD contains 378,360 CVE records. Because of this, its APIs enforce offset-based pagination to answer requests for large collections. Through a series of smaller “chunked” responses controlled by an offset startIndex and a page limit resultsPerPage users may page through all the CVE in the NVD.

The URL stem for retrieving CVE information is shown below.

Base URL
https://services.nvd.nist.gov/rest/json/cves/2.0
 Parameters
cpeName optional
{name}
This parameter returns all CVE associated with a specific CPE. The exact value provided with cpeName is compared against the CPE Match Criteria within a CVE applicability statement. If the value of cpeName is considered to match, the CVE is included in the results.

A CPE Name is a string of characters comprised of 13 colon separated values that describe a product. In CPEv2.3 the first two values are always “cpe” and “2.3”. The 11 values that follow are referred to as the CPE components. When filtering by cpeName the part, vendor, product, and version components are required to contain values other than "*".

CPE Match Criteria comes in two forms: CPE Match Strings and CPE Match String Ranges. Both are abstract concepts that are then correlated to CPE URIs in the Official CPE Dictionary. Unlike a CPE Name, match strings and match string ranges do not require a value in the part, vendor, product, or version components. The CVE API returns CPE Match Criteria within the configurations object.

Request the CVE associated a specific CPE
https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*

Request the CVE associated a specific CPE using an incomplete name
https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:o:microsoft:windows_10:1607 
cveId optional (deprecated, see cveIds)
{CVE-ID}
This parameter returns a specific vulnerability identified by its unique Common Vulnerabilities and Exposures identifier (the CVE ID). cveId will not accept {CVE-ID} for vulnerabilities not yet received by the NVD. This parameter has been deprecated by cveIds.

Request a specific CVE using its CVE-ID
https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-1010218
cveIds optional
{list of comma separated CVE-ID}
This parameter returns one or more vulnerabilities identified by a comma separated list of Common Vulnerabilities and Exposures identifier (the CVE IDs). cveIds will not accept {CVE-IDs} for vulnerabilities not yet received by the NVD. This list is limited to a maximum of 100 CVE IDs.

Request CVEs using its CVE-ID
https://services.nvd.nist.gov/rest/json/cves/2.0?cveIds=CVE-2019-1010218,CVE-2019-1010
vulnStatuses optional
UndergoingAnalysis
Modified
AwaitingAnalysis
Rejected
Received
Analyzed
Deferred
This parameter returns all CVEs in the given status. Multiple statuses are supported, with each status delimited by a comma. See NVD API documentation for mapping of NVD API statuses to NVD web site statuses.

Request CVEs using its status
https://services.nvd.nist.gov/rest/json/cves/2.0?vulnStatuses=Modified,Analyzed
cveTag optional
disputed
unsupported-when-assigned
exclusively-hosted-service
This parameter returns only the CVE records that include the provided cveTag.

Request all CVE records that have the disputed CVE Tag
https://services.nvd.nist.gov/rest/json/cves/2.0?cveTag=disputed
cvssV2Metrics optional
{CVSSv2 vector string}
This parameter returns only the CVEs that match the provided {CVSSv2 vector string}. Either full or partial vector strings may be used. This parameter cannot be used in requests that include cvssV3Metrics or cvssv4Metrics.

Please note, as of July 2022, the NVD no longer generates new information for CVSS v2. Existing CVSS v2 information will remain in the database but the NVD will no longer actively populate CVSS v2 for new CVEs. NVD analysts will continue to use the reference information provided with the CVE and any publicly available information at the time of analysis to associate Reference Tags, information related to CVSS v3.1, CWE, and CPE Applicability statements.

Request all CVE matching the CVSSv2 vector string
https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV2Metrics=AV:N/AC:H/Au:N/C:C/I:C/A:C 

An example of a valid request for which there exists no vulnerabilities
https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV2Metrics=AV:L/AC:H/Au:M/C:N/I:N/A:N 
cvssV2Severity optional
LOW
MEDIUM
HIGH
This parameter returns only the CVEs that match the provided CVSSv2 qualitative severity rating. This parameter cannot be used in requests that include cvssV3Severity or cvssv4Severity.

Please note, as of July 2022, the NVD no longer generates new information for CVSS v2. Existing CVSS v2 information will remain in the database but the NVD will no longer actively populate CVSS v2 for new CVEs. NVD analysts will continue to use the reference information provided with the CVE and any publicly available information at the time of analysis to associate Reference Tags, information related to CVSS v3.1, CWE, and CPE Applicability statements.

Request all CVE matching the CVSSv2 qualitative severity rating of LOW
https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV2Severity=LOW 
cvssV3Metrics optional
{CVSSv3 vector string}
This parameter returns only the CVEs that match the provided {CVSSv3 vector string}. Either full or partial vector strings may be used. This parameter cannot be used in requests that include cvssV2Metrics or cvssv4Metrics.

Request all CVE matching the CVSSv3 vector string
https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Metrics=AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:L 

An example of a valid request for which there exists no vulnerabilities
https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Metrics=AV:A/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H 
cvssV3Severity optional
LOW
MEDIUM
HIGH
CRITICAL
This parameter returns only the CVEs that match the provided CVSSv3 qualitative severity rating. This parameter cannot be used in requests that include cvssV2Severity or cvssv4Severity.
Note: The NVD will not contain CVSS v3 vector strings with a severity of NONE. This is why that severity is not an included option.

Request all CVE matching the CVSSv3 qualitative severity rating of LOW
https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=LOW 
cvssV4Metrics optional
{CVSSv4 vector string}
This parameter returns only the CVEs that match the provided {CVSSv4 vector string}. Either full or partial vector strings may be used. This parameter cannot be used in requests that include cvssV2Metrics or cvssV3Severity.

An example of a valid request for which there exists no vulnerabilities
https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV4Metrics=AV:A/AC:H/PR:H/UI:N
cvssV4Severity optional
LOW
MEDIUM
HIGH
CRITICAL
This parameter returns only the CVEs that match the provided CVSSv4 qualitative severity rating. This parameter cannot be used in requests that include cvssV2Severity or cvssV3Severity.
Note: The NVD enrichment data will not contain CVSS v4 vector strings with a severity of NONE. This is why that severity is not an included option.

Request all CVE matching the CVSSv4 qualitative severity rating of HIGH
https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV4Severity=HIGH 
cweId optional
{CWE-ID}
This parameter returns only the CVE that include a weakness identified by Common Weakness Enumeration using the provided {CWE-ID}.
Note: The NVD also makes use of two placeholder CWE-ID values NVD-CWE-Other and NVD-CWE-noinfo which can also be used.

Request all CVE that include Improper Authentication
https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-287 
hasCertAlerts optional
This parameter returns the CVE that contain a Technical Alert from US-CERT. Please note, this parameter is provided without a parameter value.

Request all CVE containing a Technical Alert
https://services.nvd.nist.gov/rest/json/cves/2.0?hasCertAlerts 
hasCertNotes optional
This parameter returns the CVE that contain a Vulnerability Note from CERT/CC. Please note, this parameter is provided without a parameter value.

Request all CVE containing a Vulnerability Note from CERT/CC
https://services.nvd.nist.gov/rest/json/cves/2.0?hasCertNotes 
hasKev optional
This parameter returns the CVE that appear in CISA's Known Exploited Vulnerabilities (KEV) Catalog. Please note, this parameter is provided without a parameter value.

Request all CVE that appear in the KEV catalog
https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev 
hasOval optional
This parameter returns the CVE that contain information from MITRE's Open Vulnerability and Assessment Language (OVAL) before this transitioned to the Center for Internet Security (CIS). Please note, this parameter is provided without a parameter value.

Request all CVE containing an OVAL record
https://services.nvd.nist.gov/rest/json/cves/2.0?hasOval 
isVulnerable optional
This parameter returns only CVE associated with a specific CPE, where the CPE is also considered vulnerable. The exact value provided with cpeName is compared against the CPE Match Criteria within a CVE applicability statement. If the value of cpeName is considered to match, and is also considered vulnerable the CVE is included in the results.

If filtering by isVulnerable, cpeName is required. Please note, virtualMatchString is not accepted in requests that use isVulnerable.

Request all CVE associated a specific CPE and are marked as vulnerable
https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:o:microsoft:windows_10:1607&isVulnerable 
kevStartDate & kevEndDate optional
{kevStartDate}
{kevEndDate}
These parameters return only the CVEs that were added to the CISA Known Exploited Vulnerabilities (KEV) catalog during the specified period. If a CVE was added to the KEV catalog outside of the specified window, it will not be included. When filtering by KEV inclusion dates, both kevStartDate and kevEndDate are required.

A CVE's kevDate reflects the date it was added to the KEV catalog.

Values must be entered in the extended ISO-8601 date/time format:

[YYYY][“-”][MM][“-”][DD][“T”][HH][“:”][MM][“:”][SS][Z]
The "T" separates the date from the time. The "Z" indicates optional offset-from-UTC. If a positive offset is used (e.g., +01:00 for CET), encode the "+" as "%2B". Most user agents will handle this automatically.

Request all CVE records added to the KEV catalog between the start and end datetimes
https://services.nvd.nist.gov/rest/json/cves/2.0/?kevStartDate=2023-01-01T00:00:00.000Z&kevEndDate=2023-04-30T23:59:59.000Z
keywordExactMatch optional
By default, keywordSearch returns any CVE where a word or phrase is found in the current description.

If the value of keywordSearch is a phrase, i.e., contains more than one term, including keywordExactMatch returns only the CVEs matching the phrase exactly. Otherwise, the results will contain records having any of the terms. If filtering by keywordExactMatch, keywordSearch is required. Please note, this parameter is provided without a parameter value.

Request all CVE mentioning the exact phrase "Microsoft Outlook"
https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Microsoft Outlook&keywordExactMatch
Please note, the example above would not return a CVE unless the exact phrase "Microsoft Outlook" appears in the current description.

keywordSearch optional
{keyword(s)}
This parameter returns only the CVEs where a word or phrase is found in the current description. Descriptions associated with CVE are maintained by the CVE Assignment Team through coordination with CVE Numbering Authorities (CNAs). The NVD has no control over CVE descriptions.

Please note, empty spaces in the URL should be encoded in the request as "%20". The user agent may handle this encoding automatically. Multiple {keywords} function like an 'AND' statement. This returns results where all keywords exist somewhere in the current description, though not necessarily together. Keyword search operates as though a wildcard is placed after each keyword provided. For example, providing "circle" will return results such as "circles" but not "encircle".

Request any CVE mentioning "Microsoft"
https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Microsoft 

Request any CVE mentioning "Windows", "MacOs", and "Debian"
https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Windows MacOs Linux 
lastModStartDate & lastModEndDate optional
{start date}
{end date}
These parameters return only the CVEs that were last modified during the specified period. If a CVE has been modified more recently than the specified period, it will not be included in the response. If filtering by the last modified date, both lastModStartDate and lastModEndDate are required. The maximum allowable range when using any date range parameters is 120 consecutive days.

A CVE's lastModified changes when any of the follow actions occur:

The NVD publishes the new CVE record
The NVD changes the status of a published CVE record after it has been analyzed
A source (CVE Primary CNA or another CNA) modifies a published CVE record
A CVE's lastModified does not change when any of the follow actions occur:

The NVD changes the status of a newly published CVE record to "Undergoing Analysis"
The NVD modifies a CPE record previously associated with the CVE record
Values must be entered in the extended ISO-8601 date/time format:

[YYYY][“-”][MM][“-”][DD][“T”][HH][“:”][MM][“:”][SS][Z]
The "T" is a literal to separate the date from the time. The Z indicates an optional offset-from-UTC. Please note, if a positive Z value is used (such as +01:00 for Central European Time) then the "+" should be encoded in the request as "%2B". The user agent may handle this encoding automatically.

Request all CVE records modified between the start and end datetimes
https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate=2021-08-04T13:00:00.000%2B01:00&lastModEndDate=2021-10-22T13:36:00.000%2B01:00
noRejected optional
By default, the CVE API includes CVE records with the REJECT or Rejected status. This parameter excludes CVE records with the REJECT or Rejected status from API response. Please note, this parameter is provided without a parameter value.

Request all CVE without the REJECT or Rejected status
https://services.nvd.nist.gov/rest/json/cves/2.0?noRejected 
pubStartDate & pubEndDate optional
{start date}
{end date}
These parameters return only the CVEs that were added to the NVD (i.e., published) during the specified period. If filtering by the published date, both pubStartDate and pubEndDate are required. The maximum allowable range when using any date range parameters is 120 consecutive days.

Values must be entered in the extended ISO-8601 date/time format:

[YYYY][“-”][MM][“-”][DD][“T”][HH][“:”][MM][“:”][SS][Z]
The "T" is a literal to separate the date from the time. The Z indicates an optional offset-from-UTC. Please note, if a positive Z value is used (such as +01:00 for Central European Time) then the "+" should be encoded in the request as "%2B". The user agent may handle this encoding automatically.

Request all CVE published between the start and end dates, defaulting to GMT
https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate=2021-08-04T00:00:00.000&pubEndDate=2021-10-22T00:00:00.000

Request all CVE published between the start and end datetimes
https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate=2020-01-01T00:00:00.000-05:00&pubEndDate=2020-01-14T23:59:59.999-05:00
resultsPerPage optional
{page limit}
This parameter specifies the maximum number of CVE records to be returned in a single API response. For network considerations, the default value and maximum allowable limit is 2,000.

It is recommended that users of the CVE API use the default resultsPerPage value. This value has been optimized to allow the greatest number of results over the fewest number of requests.

startIndex optional
{offset}
This parameter specifies the index of the first CVE to be returned in the response data. The index is zero-based, meaning the first CVE is at index zero.

The CVE API returns four primary objects in the response body that are used for pagination: resultsPerPage, startIndex, totalResults, and vulnerabilities. totalResults indicates the total number of CVE records that match the request parameters. If the value of totalResults is greater than the value of resultsPerPage, there are more records than could be returned by a single API response and additional requests must update the startIndex to get the remaining records.

The best, most efficient, practice for keeping up to date with the NVD is to use the date range parameters to request only the CVEs that have been modified since your last request.

Request 20 CVE records, beginning at index 0 and ending at index 19
https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=20&startIndex=0

Request the CVE records, beginning at index 20 and ending at index 39
https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=20&startIndex=20
sourceIdentifier optional
{sourceIdentifier}
This parameter returns CVE where the exact value of {sourceIdentifier} appears as a data source in the CVE record. The CVE API returns {sourceIdentifier} values within the descriptions object. The Source API returns detailed information on the organizations that provide the data contained in the NVD dataset, including every valid {sourceIdentifier} value.

Request all CVE with the data source "cve@mitre.org"
https://services.nvd.nist.gov/rest/json/cves/2.0?sourceIdentifier=cve@mitre.org
versionEnd & versionEndType optional
{ending version}
including
excluding
The virtualMatchString parameter may be combined with versionEnd and versionEndType to return only the CVEs associated with CPEs in specific version ranges.

If filtering by the ending version, versionEnd, versionEndType, and virtualMatchString are required. Requests that include versionEnd cannot include a version component in the virtualMatchString.

Request all CVE affiliated with version 2.6 of a specific CPE
https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:o:linux:linux_kernel&versionStart=2.6&versionStartType=including&versionEnd=2.7&versionEndType=excluding
versionStart & versionStartType optional
{starting version}
including
excluding
The virtualMatchString parameter may be combined with versionStart and versionStartType to return only the CVEs associated with CPEs in specific version ranges.

If filtering by the starting version, versionStart, versionStartType, and virtualMatchString are required. Requests that include versionStart cannot include a version component in the virtualMatchString.

Request all CVE affiliated with versions 2.2 through 2.5.x of a specific CPE
https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:o:linux:linux_kernel&versionStart=2.2&versionStartType=including&versionEnd=2.6&versionEndType=excluding
virtualMatchString optional
{cpe match string}
This parameter filters CVE more broadly than cpeName. The exact value of {cpe match string} is compared against the CPE Match Criteria present on CVE applicability statements.

CPE Match Criteria comes in two forms: CPE Match Strings and CPE Match String Ranges. Both are abstract concepts that are then correlated to CPE URIs in the Official CPE Dictionary. Unlike a CPE Name, match strings and match string ranges do not require a value in the part, vendor, product, or version components. The CVE API returns CPE Match Criteria within the configurations object.

CPE Match String Ranges are only supported for the version component and only when virtualMatchString is combined with versionStart, versionStartType, and/or versionEnd, both versionEndType.

cpeName is a simpler alternative for many use cases. When both cpeName and virtualMatchString are provided, only the cpeName is used.