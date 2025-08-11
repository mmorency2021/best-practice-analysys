# Red Hat Kubernetes Best Practices Analysis - Reusable Prompt

## Overview
This prompt generates a comprehensive analysis of Red Hat Best Practices Test Suite for Kubernetes/OpenShift, including detailed test case breakdowns, impact analysis, and authoritative references.

## Primary Sources
- **CertSuite Catalog**: https://github.com/redhat-best-practices-for-k8s/certsuite/blob/main/CATALOG.md
- **Best Practices Guide**: https://redhat-best-practices-for-k8s.github.io/guide/#k8s-best-practices-openshift-platform

## Prompt Instructions

### Task Definition
Analyze the Red Hat Best Practices Test Suite for Kubernetes and provide a comprehensive documentation covering each test case with detailed impact analysis and authoritative references.

### Required Analysis Structure

#### 1. Executive Summary
- Total number of test cases (119)
- Number of test suites (10)
- Workload scenario categories: Telco, Non-Telco, Far-Edge, Extended
- High-level overview table of all suites with test counts and focus areas

#### 2. Detailed Suite Analysis
For **each of the 10 test suites**, provide:

**Suite Header Format:**
```markdown
## 🔒 [Suite Name] ([X] Tests)
[Brief description of suite purpose and focus]
```

**Subsection Organization:**
Group related tests into logical subsections (e.g., "Security Context & Capabilities", "Host Resource Access Prevention")

**Table Structure (CRITICAL - 4 columns required):**
```markdown
| Test ID | Description | Impact if Failing | References |
|---------|-------------|------------------|------------|
```

#### 3. Impact Severity Classifications
Use these **exact severity levels** with consistent formatting:
- **Critical**: System compromise, container escape, privilege escalation
- **High**: Security/availability risks, missing probes, uncertified components  
- **Medium**: Operational issues, configuration drift, performance degradation
- **Low**: Best practice violations, documentation issues

#### 4. References Column Requirements
For each test case, provide **1-2 authoritative reference links** covering:
- **Security Tests**: Kubernetes Security Docs, NIST SP 800-190, Container Security Best Practices, CIS Benchmarks
- **Capabilities**: Linux Capabilities Manual, Pod Security Standards
- **Networking**: Network Policies, CNI Security Considerations, Service Mesh Security
- **Performance**: CPU Management Policies, Performance Tuning Guides
- **Compliance**: Red Hat Certification, Platform Documentation, FIPS Compliance
- **Lifecycle**: Health Checks, Graceful Shutdown, Pod Lifecycle Management
- **RBAC**: Access Control Documentation, Service Account Security
- **Platform**: SELinux Documentation, Universal Base Images, System Security

#### 5. Additional Required Sections

**Impact Summary by Severity:**
```markdown
## 📈 Impact Summary by Severity

### Critical Impact (System Compromise)
- [List critical failure types]

### High Impact (Security/Availability Risk)  
- [List high impact failure types]

### Medium Impact (Operational Issues)
- [List medium impact failure types]

### Low Impact (Best Practice Violations)
- [List low impact failure types]
```

**Remediation Priority Matrix:**
```markdown
## 🎯 Remediation Priority Matrix

| Priority | Focus Area | Key Actions |
|----------|------------|-------------|
| **P0** | Security Fundamentals | [Actions] |
| **P1** | Platform Compliance | [Actions] |
| **P2** | Lifecycle Management | [Actions] |
| **P3** | Resource Management | [Actions] |
| **P4** | Observability | [Actions] |
```

**Quick Remediation Guide:**
Include YAML code examples for:
- Security hardening (securityContext)
- Lifecycle configuration (probes, resources)
- Network security (NetworkPolicy)

#### 6. Comprehensive References Section
Organize into categories:
- Security Best Practices Documentation
- Capability Management & Linux Security  
- Networking & Isolation
- Resource Management & Performance
- Observability & Monitoring
- RBAC & Authentication
- Compliance & Certification
- Lifecycle Management
- Platform Integration
- Impact Analysis Resources

### Output Format Requirements

#### Markdown Version (.md)
- **File Purpose**: GitHub repository documentation
- **Format**: Standard GitHub Markdown with tables
- **Tables**: 4-column structure with proper alignment
- **Links**: Full hyperlinks with descriptive text `[Link Text](URL)`
- **Code Blocks**: YAML examples with proper syntax highlighting
- **Emojis**: Use section emojis (🔒, 🔗, 🔄, etc.) for visual organization

### Quality Standards

#### Content Requirements
1. **Accuracy**: All test IDs must match official CertSuite catalog
2. **Completeness**: Cover all 119 test cases across 10 suites
3. **Consistency**: Use standardized impact severity levels
4. **Authority**: Reference only official Kubernetes, Red Hat, and industry documentation
5. **Actionability**: Include practical remediation guidance

#### Reference Link Standards
- **Primary Sources**: Official Kubernetes.io documentation
- **Security**: NIST, CIS Benchmarks, MITRE ATT&CK framework
- **Platform**: Red Hat official documentation and guides
- **Industry**: Established security and containerization best practices
- **Avoid**: Blog posts, unofficial tutorials, outdated documentation

### Test Suite Breakdown (Reference)
Ensure coverage of all these suites:

1. **access-control** (28 tests): Security, capabilities, RBAC
2. **affiliated-certification** (4 tests): Red Hat certification compliance  
3. **lifecycle** (18 tests): Pod management, scaling, availability
4. **manageability** (2 tests): Operational management
5. **networking** (12 tests): Network policies, connectivity
6. **observability** (5 tests): Monitoring, logging
7. **operator** (12 tests): Operator best practices
8. **performance** (6 tests): Resource optimization
9. **platform-alteration** (14 tests): Platform compliance
10. **preflight** (18 tests): Pre-deployment validation

### Execution Steps

#### Step 1: Data Collection
```
1. Fetch the CertSuite catalog from GitHub
2. Parse all test case definitions and metadata
3. Extract test IDs, descriptions, and categorizations
4. Cross-reference with Best Practices Guide
```

#### Step 2: Analysis & Categorization  
```
1. Group tests by suite and logical subsections
2. Assign impact severity levels based on failure consequences
3. Research authoritative references for each test type
4. Develop remediation guidance and examples
```

#### Step 3: Content Generation
```
1. Create executive summary with statistics
2. Generate detailed suite-by-suite analysis
3. Build comprehensive reference tables with 4-column structure
4. Add remediation guides and code examples
5. Compile comprehensive references section
```

#### Step 4: Quality Assurance
```
1. Verify all 119 test cases are covered
2. Ensure consistent formatting and severity levels
3. Validate all reference links are active and authoritative
4. Review for completeness and accuracy
```

#### Step 5: Output Generation
```
1. Generate Markdown version for GitHub repository
2. Ensure proper formatting and table structure
3. Validate syntax highlighting for code blocks
4. Test markdown rendering compatibility
```

### Expected Deliverables

#### Output
- **Comprehensive Markdown file** (35,000+ words)
- **119 test cases** fully documented
- **200+ authoritative reference links**
- **Practical remediation guidance**
- **Professional formatting** ready for GitHub

### Success Criteria
- ✅ All 119 test cases documented with impact analysis
- ✅ 4-column table structure with References column
- ✅ Authoritative links for each test case impact
- ✅ Consistent severity classifications
- ✅ Practical remediation examples
- ✅ Professional formatting suitable for enterprise use
- ✅ GitHub-ready Markdown documentation

### Usage Instructions
1. **Input the complete prompt** to your AI assistant
2. **Provide the two source URLs** for data extraction
3. **Specify Markdown output format** 
4. **Request GitHub repository push** if needed
5. **Review and validate** the generated content for accuracy

### Notes
- This analysis covers **Red Hat CertSuite v5.5.7** test framework
- Focus on **Cloud Native Functions (CNFs)** deployment best practices  
- Target audience: **DevOps teams, Platform engineers, Security professionals**
- Update references periodically as Kubernetes documentation evolves
- Output format: **Markdown only** for GitHub repository documentation

---

*Prompt Version: 1.0 | Compatible with: Red Hat CertSuite v5.5.7 | Last Updated: $(date)*