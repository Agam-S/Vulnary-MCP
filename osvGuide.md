For POST /v1/query

 PARAMETERS
 Parameter	Type	Description
 commit	string	The commit hash to query for. If specified, version should not be set.
 version	string	The version string to query for. A fuzzy match is done against upstream versions. If set, commit must not be used, and package.purl must not include a version.
 package	object	The package to query against. When a commit hash is given, this is optional.
 page_token	string	If your previous query fetched a large number of results, the response will be paginated. This is an optional field. Please see the pagination section for more information.

 Attribute	Type	Description
 name	string	Name of the package. Should match the name used in the package ecosystem (e.g. the npm package name). For C/C++ projects integrated in OSS-Fuzz, this is the name used for the integration. If using name to specify the package, ecosystem must also be used and purl should not be set.
 ecosystem	string	The ecosystem for this package. For the complete list of valid ecosystem names, see here. Must be included if identifying the package by name. If specifying by name and ecosystem, purl should not be set.
 purl	string	The package URL for this package. If purl is used to specify the package, name and ecosystem should not be set.

 Examples
 { "package": { "name": "jinja2", "ecosystem": "PyPI" }, "version": "3.1.4" }
 { "package": { "purl": "pkg:pypi/jinja2@3.1.4" } }
 { "package": { "purl": "pkg:pypi/jinja2" }, "version": "3.1.4" }

 Sample request body for a package query:
 {
   "vulns": [
     {
       "id": "OSV-2020-744",
       "summary": "Heap-double-free in mrb_default_allocf",
       "details": "OSS-Fuzz report: https:bugs.chromium.org/p/oss-fuzz/issues/detail?id=23801\n\n```\nCrash type: Heap-double-free\nCrash state:\nmrb_default_allocf\nmrb_free\nobj_free\n```\n",
       "modified": "2022-04-13T03:04:39.780694Z",
       "published": "2020-07-04T00:00:01.948828Z",
       "references": [
         {
           "type": "REPORT",
           "url": "https:bugs.chromium.org/p/oss-fuzz/issues/detail?id=23801"
         }
       ],
       "affected": [
         {
           "package": {
             "name": "mruby",
             "ecosystem": "OSS-Fuzz",
             "purl": "pkg:generic/mruby"
           },
           "ranges": [
             {
               "type": "GIT",
               "repo": "https:github.com/mruby/mruby",
               "events": [
                 {
                   "introduced": "9cdf439db52b66447b4e37c61179d54fad6c8f33"
                 },
                 {
                   "fixed": "97319697c8f9f6ff27b32589947e1918e3015503"
                 }
               ]
             }
           ],
           "versions": [
             "2.1.2",
             "2.1.2-rc",
             "2.1.2-rc2"
           ],
           "ecosystem_specific": {
             "severity": "HIGH"
           },
           "database_specific": {
             "source": "https:github.com/google/oss-fuzz-vulns/blob/main/vulns/mruby/OSV-2020-744.yaml"
           }
         }
       ],
       "schema_version": "1.4.0"
     }
   ]
 }


POST /v1/querybatch

    Payload
    {
    "queries": [
        {
        "commit": "string",
        "version": "string",
        "package": {
            "name": "string",
            "ecosystem": "string",
            "purl": "string"
        },
        "page_token": "string",
        }, 
        {
        "commit": "string",
        "version": "string",
        "package": {
            "name": "string",
            "ecosystem": "string",
            "purl": "string"
        },
        "page_token": "string",
        }
    ]
    }


    Request Sample
    cat <<EOF | curl -d @- "https://api.osv.dev/v1/querybatch"
    {
    "queries": [
        {
        "package": {
            "purl": "pkg:pypi/mlflow@0.4.0"
        }
        },
        {
        "commit": "6879efc2c1596d11a6a6ad296f80063b558d5e0f"
        },
        {
        "package": {
            "ecosystem": "PyPI",
            "name": "jinja2"
        },
        "version": "2.4.1"
        }
    ]
    }
    EOF


    Sample Response
    {
    "results":
        [
        {
            "vulns":
            [
                {
                "id":"GHSA-vqj2-4v8m-8vrq",
                "modified":"2023-03-14T05:47:39.989396Z"
                },
                {
                "id":"GHSA-wp72-7hj9-5265",
                "modified":"2023-03-24T22:28:29.389429Z"
                },
                {
                "id":"GHSA-xg73-94fp-g449",
                "modified":"2023-03-24T22:54:55.516821Z"
                },
                {
                "id":"PYSEC-2022-28",
                "modified":"2022-03-02T06:39:30.836439Z"
                }
            ]
        },
        {
            "vulns":
            [
                {
                "id":"OSV-2020-484",
                "modified":"2022-04-13T03:04:32.842142Z"
                }
            ]
        },
        {
            "vulns":
            [
                {
                "id":"GHSA-462w-v97r-4m45",
                "modified":"2023-03-10T05:23:41.874079Z"
                },
                {
                "id":"GHSA-8r7q-cvjq-x353",
                "modified":"2023-03-08T05:47:11.461578Z"
                },
                {
                "id":"GHSA-fqh9-2qgg-h84h",
                "modified":"2023-03-09T05:31:42.262435Z"
                },
                {
                "id":"GHSA-g3rq-g295-4j3m",
                "modified":"2023-03-12T05:29:26.243227Z"
                },
                {
                "id":"GHSA-hj2j-77xm-mc5v",
                "modified":"2023-03-12T05:32:53.675797Z"
                },
                {
                "id":"PYSEC-2014-8",
                "modified":"2021-07-05T00:01:22.043149Z"
                },
                {
                "id":"PYSEC-2014-82",
                "modified":"2021-08-27T03:22:05.027573Z"
                },
                {
                "id":"PYSEC-2019-217",
                "modified":"2021-11-22T04:57:52.862665Z"
                },
                {
                "id":"PYSEC-2019-220",
                "modified":"2021-11-22T04:57:52.929678Z"
                },
                {
                "id":"PYSEC-2021-66",
                "modified":"2021-03-22T16:34:00Z"
                }
            ]
            }
        ]
    }


    Pagination
    {
    "results": [
        {
        "vulns": [
            ...
        ],
        "next_page_token": "token for query 1"
        },
        {
        "vulns": [
            ...
        ],
        "next_page_token": "token for query 2"
        },
        {
        "vulns": [
            ...
        ],
        },
        ...
    ]
    }


GET /v1/vulns/{id}

    Request Sample 
    curl "https://api.osv.dev/v1/vulns/OSV-2020-111"

    Sample Response
    {
    "id": "OSV-2020-111",
    "summary": "Heap-use-after-free in int std::__1::__cxx_atomic_fetch_sub<int>",
    "details": "OSS-Fuzz report: https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=21604\n\n```\nCrash type: Heap-use-after-free WRITE 4\nCrash state:\nint std::__1::__cxx_atomic_fetch_sub<int>\nstd::__1::__atomic_base<int, true>::operator--\nObject::free\n```\n",
    "modified": "2022-04-13T03:04:37.331327Z",
    "published": "2020-06-24T01:51:14.570467Z",
    "references": [
        {
        "type": "REPORT",
        "url": "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=21604"
        }
    ],
    "affected": [
        {
        "package": {
            "name": "poppler",
            "ecosystem": "OSS-Fuzz",
            "purl": "pkg:generic/poppler"
        },
        "ranges": [
            {
            "type": "GIT",
            "repo": "https://anongit.freedesktop.org/git/poppler/poppler.git",
            "events": [
                {
                "introduced": "e4badf4d745b8e8f9a0a25b6c3cc97fbadbbb499"
                },
                {
                "fixed": "155f73bdd261622323491df4aebb840cde8bfee1"
                }
            ]
            }
        ],
        "ecosystem_specific": {
            "severity": "HIGH"
        },
        "database_specific": {
            "source": "https://github.com/google/oss-fuzz-vulns/blob/main/vulns/poppler/OSV-2020-111.yaml"
        }
        }
    ],
    "schema_version": "1.4.0"
    }
