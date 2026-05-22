# Configuration

This document provides a comprehensive list of all configuration parameters available for the **Facepalm Maven Plugin**.

## Core Parameters

These parameters control the basic execution of the scan.

| Parameter | Property | Default | Description |
|-----------|----------|---------|-------------|
| `root` | `root` | `${project.basedir}` | Root directory for scanning. |
| `threads` | `threads` | Available Processors | Concurrent threads for scanning. |
| `maxFileSizeBytes` | `maxFileSizeBytes` | `5242880` (5MB) | Maximum file size in bytes; larger files are ignored. |
| `skipBinaryRegex` | `skipBinaryRegex` | `.*\\.(png\|jpg\|jpeg\|gif\|pdf\|zip\|jar\|class\|tar\|gz\|exe\|dll)$` | Regex to identify binary files to skip. |
| `skipDirs` | `skipDirs` | `.git, .idea` | Directories to exclude from scanning (comma-separated via CLI). |
| `showProcessed` | `showProcessed` | `false` | Log every processed file at debug level. |
| `showSkipped` | `showSkipped` | `false` | Log every skipped file at debug level. |

## Scoring & Thresholds

Facepalm uses a scoring engine (0-100) to determine if a finding is critical.

| Parameter | Property | Default | Description |
|-----------|----------|---------|-------------|
| `strategy` | `scoring.strategy` | `WEIGHTED_QUADRATIC` | Strategy used to combine risk and confidence. Available values: `AVERAGE`, `GEOMETRIC`, `ROOT_MEAN_SQUARE`, `WEIGHTED_QUADRATIC`, `GATEKEEPER`. |
| `errorThreshold` | `errorThreshold` | `80` | Score threshold for high-risk findings (Critical). |
| `warningThreshold` | `warningThreshold` | `40` | Score threshold for moderate-risk findings (Warning). |
| `showScoring` | `showScoring` | `false` | Log detailed scoring breakdowns for each finding. |
| `showDetails` | `showDetails` | `false` | Log discovery and exclusion statistics. |
| `failOnError` | `failOnError` | `true` | Fail the build if any finding reaches the error threshold. |
| `failOnWarnings` | `failOnWarnings` | `false` | Fail the build if any finding reaches the warning threshold. |

## Advanced Configuration

### Heuristics (`<evaluators>`)

Refine how Facepalm evaluates risk and legitimacy.

| Sub-parameter | Default                                         | Description |
|---------------|-------------------------------------------------|-------------|
| `interpolationPatternRegex` | `.*?(?:\$\{.*}\|\{\{.*\}\|<.*>\|%.*%\|\[.*]).*` | Regex to detect placeholders like `${API_KEY}`. |
| `highRiskExtensions` | `.env, .properties, .yml, .yaml, .conf, .ini`   | Extensions that increase the risk score. |
| `lowRiskExtensions` | `.md, .txt, .csv, .log, .example, .sample`      | Extensions that decrease the risk score. |
| `dummyKeywords` | `dummy, your_api_key, insert_here, ...`         | Keywords indicating fake data. |
| `prodPathMarkers` | `src/main/, .env, config`                       | Path segments indicating production environments. |
| `testPathMarkers` | `test, mock, spec`                              | Path segments indicating test environments. |
| `prodContextMarkers` | `prod, live`                                    | Surrounding code keywords indicating production use. |
| `mockContextMarkers` | `example, dummy, fake, mock`                    | Surrounding code keywords indicating mock use. |

### Post-Processing (`<postProcessing>`)

Noise reduction settings.

| Sub-parameter | Default | Description |
|---------------|---------|-------------|
| `highVolumeThreshold` | `15` | Max occurrences allowed before a secret is suppressed as noise. |

---

## Example `pom.xml`

```xml
<plugin>
    <groupId>dev.nichar</groupId>
    <artifactId>facepalm-maven-plugin</artifactId>
    <version>1.0-SNAPSHOT</version>
    <configuration>
        <errorThreshold>85</errorThreshold>
        <failOnWarnings>true</failOnWarnings>
        <skipDirs>target,bin,logs</skipDirs>
        <evaluators>
            <dummyKeywords>
                <keyword>test_key</keyword>
                <keyword>fake_secret</keyword>
            </dummyKeywords>
        </evaluators>
    </configuration>
</plugin>
```

## CLI Usage

You can override parameters directly from the command line:

```bash
mvn facepalm:scan -DskipDirs=target,dist -DfailOnWarnings=true -DshowDetails=true
```
