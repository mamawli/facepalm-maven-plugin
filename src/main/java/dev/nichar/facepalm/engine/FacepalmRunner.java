/*
 * Licensed under Apache-2.0.
 * Copyright (c) 2026 Nikolas Charalambidis.
 * All rights reserved.
 */

package dev.nichar.facepalm.engine;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.nichar.facepalm.FacepalmConfig;
import dev.nichar.facepalm.config.ScoringConfig;
import dev.nichar.facepalm.report.FindingReport;
import dev.nichar.facepalm.report.Reporter;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import java.io.File;
import java.nio.file.Path;
import java.util.List;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.plugin.logging.SystemStreamLog;

/**
 * Orchestrates the scanning lifecycle.
 * Manages gitignore discovery, extraction, scoring, and report serialization.
 */
@Named
@Singleton
public class FacepalmRunner {

    @Inject
    private @Nullable Log log;

    @Inject
    private FacepalmConfig context;

    @Inject
    private ScannerEngine engine;

    @Inject
    private GitIgnoreService gitIgnoreService;

    @Inject
    private Reporter reporter;

    private Log getLog() {
        return log != null ? log : new SystemStreamLog();
    }

    /**
     * Executes the end-to-end scanning workflow.
     * Evaluates build failure conditions based on discovery results.
     *
     * @param root Base directory to scan.
     * @param outputDir Target directory for findings and reports.
     * @param version Scanner version for metadata.
     */
    public void run(@Nonnull final Path root,
                    @Nonnull final Path outputDir,
                    @Nonnull final String version) throws Exception {

        getLog().info("Scanning " + root);

        gitIgnoreService.loadAllGitIgnores(root);
        final var findings = engine.scan(root);
        final var stats = engine.getStats();

        reporter.printLogs(stats, findings);

        // Persist findings for downstream report generation.
        final var resultsFile = new File(outputDir.toFile(), "facepalm-findings.json");
        saveFindingsToJson(findings, resultsFile);

        // Enforce build failure policies based on finding severity.
        final var scoring = context.getScoring();
        final long errors = findings.stream().filter(f -> f.getSeverity(scoring) == Severity.ERROR).count();
        final long warnings = findings.stream().filter(f -> f.getSeverity(scoring) == Severity.WARNING).count();
        checkFailureConditions(errors, warnings);
    }

    /**
     * Serializes findings to a machine-readable JSON format for the reporting phase.
     */
    private void saveFindingsToJson(@Nonnull final List<Finding> findings, @Nonnull final File outputFile)
            throws Exception {
        if (!outputFile.getParentFile().exists()) {
            outputFile.getParentFile().mkdirs();
        }

        final var findingsDto = findings.stream()
            .map(finding -> mapToDto(finding, context.getScoring()))
            .toList();

        final var mapper = new ObjectMapper();
        mapper.writerWithDefaultPrettyPrinter().writeValue(outputFile, findingsDto);
    }

    /**
     * Maps a raw scan finding to a serializable DTO.
     */
    @Nonnull
    public FindingReport mapToDto(@Nonnull final Finding finding, @Nonnull final ScoringConfig config) {
        return FindingReport.builder()
            .patternName(finding.getPatternName())
            .fileAbsolutePath(finding.getContext().getPath().toAbsolutePath().toString())
            .lineNumber(finding.getLineNumber())
            .maskedSecret(finding.getMaskedSecret())
            .contextSnippet(finding.getContextSnippet())
            .finalScore(finding.getNumericScore(config))
            .finalSeverity(finding.getSeverity(config).name())
            .riskScore(finding.getRiskScore())
            .confidenceScore(finding.getConfidenceScore())
            .build();
    }

    /**
     * Terminates the build if findings exceed configured threat thresholds.
     */
    private void checkFailureConditions(final long errors, final long warnings) throws MojoFailureException {
        final var scoring = context.getScoring();
        if (!scoring.isFailOnError() && scoring.isFailOnWarnings()) {
            getLog().warn("Unusual configuration: failOnError=false with failOnWarnings=true");
        }
        if (scoring.isFailOnError() && errors > 0) {
            throw new MojoFailureException("Facepalm scan failed: " + errors + " critical findings detected.");
        }
        if (scoring.isFailOnWarnings() && warnings > 0) {
            throw new MojoFailureException("Facepalm scan failed: " + warnings
                + " warnings detected and failOnWarnings is true.");
        }
    }
}
