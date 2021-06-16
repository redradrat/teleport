## Documentation Layout

This page is useful for tracking content changes across versions.

Oftentimes, we'll want to trim or combine content.

It also describes all article subsections and video content in one quick view to make planning easier.

### Blogs and READMEs

- Blogs live in https://github.com/gravitational/web and are hosted live at https://goteleport.com/blog/.
- READMEs live in the root directory of each GitHub repository.

### Meta-Documentation

- Meta Documentation Section
  - [Documentation Quicks Start](https://goteleport.com/docs/docs/)
  - [Documentation Best Practices](https://goteleport.com/docs/docs/best-practices/)

### Products Supported

Our current Product and Reference Documentation topics are divided into thirteen (13) sections supporting the four (4) main products:

1. Teleport Application Access
2. Teleport Server Access
3. Teleport Database Access
4. Teleport Kubernetes Access

Along with a fifth for:

5. Teleport Cloud

### Product and Reference Documentation (Article-Level)

The documentation layout and structure is presently:

- [ ] Home Section
    - [ ] Introduction
    - [ ] Adopters
    - [ ] Getting Started
    - [ ] Installation
    - [ ] User Manual
    - [ ] Admin Manual
    - [ ] Production Guide
    - [ ] FAQ
    - [ ] Changelog
- [ ] Setup Section
    - [ ] Guides
        - [ ] Terraform Provider
        - [ ] Local Docker
- [ ] Application Access Section
    - [ ] Introduction
    - [ ] Getting Started
    - [ ] Guides
        - [ ] Connecting Web Apps
        - [ ] Integrating with JWTs
        - [ ] Application API Access
    - [ ] Access Controls
    - [ ] Reference
- [ ] Server Access Section
    - [ ] Introduction
    - [ ] Getting Started
    - [ ] Guides
        - [ ] Using Teleport with PAM
        - [ ] OpenSSH Guide
- [ ] Kubernetes Access Section
    - [ ] Introduction
    - [ ] Getting Started
    - [ ] Guides
        - [ ] Multiple Clusters
        - [ ] CI/CD
        - [ ] Federation
        - [ ] Migration
        - [ ] Standalone
    - [ ] Helm Guides
        - [ ] AWS EKS Cluster
        - [ ] Google Cloud GKE Cluster
        - [ ] Customize Deployment Config
        - [ ] Migration From Older Charts
    - [ ] Helm Chart Reference
    - [ ] Access Controls
- [ ] Database Access Section
    - [ ] Introduction
    - [ ] Getting Started
    - [ ] Guides
        - [ ] AWS RDS/Aurora PostgresSQL
        - [ ] AWS RDS/Aurora MySQL
        - [ ] AWS Redshift PostgresSQL
        - [ ] GCP Cloud SQL PostgresSQL
        - [ ] Self-Hosted PostgreSQL
        - [ ] Self-Hosted MySQL
        - [ ] Database GUI Clients
    - [ ] Access Controls
    - [ ] Architecture
    - [ ] Reference
        - [ ] Configuration
        - [ ] CLI
        - [ ] Audit Events
    - [ ] FAQ
- [ ] Access Controls Section
    - [ ] Introduction
    - [ ] Getting Started
    - [ ] Guides
       - [ ] Role Templates
        - [ ] Second Factor - U2F
        - [ ] Per-session MFA
        - [ ] Dual Authorization
        - [ ] Impersonation
    - [ ] Reference
    - [ ] FAQ
- [ ] Preview Section
    - [ ] Upcoming Releases
- [ ] Infrastructure Guides Section
    - [ ] AWS
    - [ ] AWS Terraform
    - [ ] GCP
    - [ ] IBM
- [ ] Teleport Enterprise Section
    - [ ] Introduction
    - [ ] Quick Start Guide
    - [ ] Single Sign-On (SSO)
        - [ ] Azure Active Directory (AD)
        - [ ] Active Directory (ADFS)
        - [ ] Google Workspace
        - [ ] GitLab
        - [ ] OneLogin
        - [ ] OIDC
        - [ ] Okta
    - [ ] Access Requests
        - [ ] Integrating Teleport with Slack
        - [ ] Integrating Teleport with Mattermost
        - [ ] Integrating Teleport with Jira Cloud
        - [ ] Integrating Teleport with Jira Server
        - [ ] Integrating Teleport with PagerDuty
    - [ ] FedRAMP for SSH & K8s
    - [ ] Role-Based Access Control
- [ ] Cloud Section
    - [ ] Introduction
    - [ ] Getting Started
    - [ ] Architecture
    - [ ] Teleport Cloud FAQ
- [ ] Architecture Section
    - [ ] Architecture Overview
    - [ ] Teleport Users
    - [ ] Teleport Nodes
    - [ ] Teleport Auth
    - [ ] Teleport Proxy
    - [ ] Trusted Clusters
- [ ] Advanced Features Section
    - [ ] Enhanced Session Recording
- [ ] Reference Section
    - [ ] YAML
    - [ ] CLI
    - [ ] Metrics
    - [ ] API
        - [ ] Teleport API Introduction
        - [ ] Getting Started
        - [ ] API Architecture

### Product and Reference Documentation (Subsection-Level)

The documentation layout and structure is presently:

- [ ] Home Section
    - [ ]  Introduction
        - [ ] What is Teleport
        - w/ Demo video
        - w/ Tile landing
    - [ ] Adopters
        - [ ] Who is using Teleport
    - [ ] Getting Started
        - [ ] Prerequisites
        - [ ] Follow along with our video guide
        - [ ] Step 1/4. Install Teleport on a Linux machine
        - [ ] Step 2/4. Create a Teleport user and set up two-factor authentication
        - [ ] Step 3/4. Log in using tsh
        - [ ] Step 4/4. Have fun with Teleport!
        - [ ] Guides
    - [ ] Installation
        - [ ] Linux
        - [ ] Docker
        - [ ] Helm
        - [ ] MacOs
        - [ ] Windows (tsh client only)
        - [ ] Installing from source
        - [ ] Checksums
        - [ ] Operating System support
    - [ ] User Manual
        - [ ] Introduction
        - [ ] Installing tsh
        - [ ] User identities
        - [ ] Logging in
        - [ ] Explorign the cluster
        - [ ] Interactive shell
        - [ ] Copying files
        - [ ] Sharing sesssions
        - [ ] Connecting to SSH clusters behind a load balancer
        - [ ] Web UI
        - [ ] Using OpenSSH client
        - [ ] Troubleshooting
        - [ ] Getting help
    - [ ] Admin Manual
        - [ ] Installing
        - [ ] Definitions
        - [ ] Teleport Daemon
        - [ ] Configuration
        - [ ] Authentication
        - [ ] Adding and deleting users
        - [ ] Editing users
        - [ ] Adding Nodes to the cluster
        - [ ] Revoking invitations
        - [ ] Adding a Node located behind NAT
        - [ ] Labeling Nodes and applications
        - [ ] Auding Log
        - [ ] Resources
        - [ ] Trusted Clusters
        - [ ] GitHub Oath 2.0
        - [ ] HTTP CONNECT proxies
        - [ ] PAM integration
        - [ ] Using Teleport with OpenSSH
        - [ ] Certificate rotation
        - [ ] Ansible integration
        - [ ] Kubernetes integration
        - [ ] Storage backeneds
        - [ ] High Availability
        - [ ] Upgrading Teleport
        - [ ] Backing up Teleport
        - [ ] GitOps
        - [ ] Migrating backends
        - [ ] License file
        - [ ] Troubleshooting
        - [ ] Getting help
    - [ ] Production Guide
        - [ ] Prerequisites
        - [ ] Designing your cluster
        - [ ] Firewall configuration
        - [ ] Installation
        - [ ] Running Teleport in production
        - [ ] Security considerations
    - [ ] FAQ
        - [ ] Community FAQ
        - [ ] Whcih version of Teleport is supported
        - [ ] Commercial Teleport Editions
        - Section-specific FAQ
    - [ ] Changelog
        - Teleport repository README is injected here.
- [ ] Setup Section
    - [ ] Guides
        - w/ Tile landing
        - [ ] Terraform Provider
            - [ ] Follow along with our video guide
            - [ ] Prerequisites
            - [ ] Step 1/4. Install terraform provider
            - [ ] Step 2/4. Create a terraform user
            - [ ] Step 3/4. Create Terraform configuration
            - [ ] Step 4/4. Apply the configuration
            - [ ] Next steps
        - [ ] Local Docker
            - [ ] Pick your image
            - [ ] Quickstart using docker-compose
            - [ ] Quickstart using docker run
            - [ ] Creating a Teleport user when using Docker quickstart
- [ ] Application Access Section
    - [ ] Introduction
        - [ ] Application Access
        - [ ] Demo
        - [ ] Getting started
        - [ ] Guides
        - [ ] Example legacy apps
        - [ ] Example modern apps
        - w/ Tile landing
        - w/ Video
    - [ ] Getting Started
        - [ ] Follow along with our video guide
        - [ ] Prerequisites
        - [ ] Step 1/3. Start Grafna
        - [ ] Step 2/3. Install and configure Teleport
        - [ ] Step 3/3. Access the application
        - [ ] Next steps
    - [ ] Guides
        - w/ Tile landing
        - [ ] Connecting Web Apps
            - [ ] Connecting Web Applications
            - [ ] Start Auth/Proxy service
            - [ ] Start application service with CLI
            - [ ] Start application service with a config file
            - [ ] Advanced options
            - [ ] View applications in Teleport
            - [ ] Logging out of applications
        - [ ] Integrating with JWTs
            - [ ] Integrating with JWTs
            - [ ] Introduction to JWTs
            - [ ] Validate JWT
        - [ ] Application API Access
            - [ ] Application API Acces
            - [ ] Prequisites
            - [ ] Accessing the API
            - [ ] Application information
    - [ ] Access Controls
        - [ ] Assinging labels to applications
        - [ ] Configuring application labels in roles
        - [ ] Integrating with identity providers
        - [ ] Next steps
    - [ ] Reference
        - [ ] Configuration
        - [ ] CLI
- [ ] Server Access Section
    - [ ] Introduction
        - [ ] Server Access
        - [ ] Demo
        - [ ] Getting started
        - [ ] Guides
        - w/ Demo video
        - w/ Tile landing
    - [ ] Getting Started
        - [ ] Getting Started
        - [ ] Prerequisites
        - [ ] Step 1/4. Create a cluster
        - [ ] Step 2/4. Add a Node to the cluster
        - [ ] Step 3/4. SSH into the server
        - [ ] Step 4/4. Use tsh and the unified resource catalog
        - [ ] Conclusion
        - [ ] Next steps
        - [ ] Resources
        - w/ Diagrams
        - w/ Screenshots
    - [ ] Guides
        - [ ] Using Teleport with PAM
            - [ ] Introduction to Pluggable Authentication Modules
            - [ ] Set up PAM on a Linux Machine running Teleport
            - [ ] Set Message of the Day (motd) with Teleport
            - [ ] Custom environment variables
            - [ ] Create local users with Teleport
            - [ ] Additional authentication steps
        - [ ] OpenSSH Guide
            - [ ] Overview
            - [ ] Set up OpenSSH recording proxy mode
            - [ ] Use OpenSSH client
            - [ ] OpenSSH rate limiting
            - [ ] Revoke an SSH certificate
- [ ] Kubernetes Access Section
    - [ ] Introduction
        - [ ] SSO and Audit for Kubernetes Clusters
        - [ ] Getting started
        - [ ] Guides
        - w/ Demo video
        - w/ Tile landing
    - [ ] Getting Started
        - [ ] Getting Started
        - [ ] Follow along with our video guide
        - [ ] Prerequisites
        - [ ] Step 1/3. Install Teleport
        - [ ] Step 2/3. Create a local admin
        - [ ] Step 3/3. SSO for Kubernetes
        - [ ] Next steps
        - w/ Demo video
    - [ ] Guides
        - w/ Tile landing
        - [ ] Multiple Clusters
            - [ ] Prerequisites
            - [ ] Connecting clusters
        - [ ] CI/CD
            - [ ] Short-Lived Certs for Kubernetes CI/CD
        - [ ] Federation
            - [ ] Federated Kubernetes access with Trusted Clusters
        - [ ] Migration
            - [ ] Example scenarios
            - [ ] RBAC
        - [ ] Standalone
            - [ ] Standalone Teleport installation
            - [ ] Generating kubeconfig
            - [ ] Adding kubeconfig to Teleport
    - [ ] Helm Guides
        - [ ] AWS EKS Cluster
            - [ ] Prerequisites
            - [ ] Step 1. Install Helm
            - [ ] Step 2. Add the Teleport Helm chart repository
            - [ ] Step 3. Set up AWS IAM configuration
            - [ ] Step 4. Install and configure cert-manager
            - [ ] Step 5. Set values to configure the cluster
            - [ ] Step 6. Set up DNS
            - [ ] Step 7. Create a Teleport user
            - [ ] Uninstalling Teleport
            - [ ] Next steps
        - [ ] Google Cloud GKE Cluster
            - [ ] Prerequisites
            - [ ] Step 1. Install Helm
            - [ ] Step 2. Add the Teleport Helm chart repository
            - [ ] Step 3: Google Cloud IAM configuration
            - [ ] Step 4. Install and configure cert-manager
            - [ ] Step 5. Set values to configure the cluster
            - [ ] Step 6. Set up DNS
            - [ ] Step 7. Create a Teleport user
            - [ ] Upgrading the cluster after deployment
            - [ ] Uninstalling Teleport
            - [ ] Next steps
        - [ ] Customize Deployment Config
            - [ ] Prerequisites
            - [ ] Step 1. Install Helm
            - [ ] Step 2. Add the Teleport Helm chart repository
            - [ ] Step 3. Setting up a Teleport cluster with Helm using a custom config
            - [ ] Step 4. Create a Teleport user (optional)
            - [ ] Upgrading the cluster after deployment
            - [ ] Uninstalling the Helm chart
            - [ ] Next steps
        - [ ] Migration From Older Charts
            - [ ] Prerequisites
            - [ ] Step 1. Install Helm
            - [ ] Step 2. Add the Teleport Helm chart repository
            - [ ] Step 3. Get the Teleport configuration file from your existing cluster
            - [ ] Step 4. Extracting the contents of Teleport's database
            - [ ] Step 5. Start the new cluster with your old config file and backup
            - [ ] Step 6. Remove the bootstrap data and update the chart deployment
            - [ ] Uninstalling Teleport
    - [ ] Helm Chart Reference
        - [ ] teleport-cluster
        - [ ] clusterName
        - [ ] enterprise
        - [ ] teleportVersionOverride
        - [ ] acme
        - [ ] acmeEmail
        - [ ] acmeURI
        - [ ] podSecurityPolicy
        - [ ] labels
        - [ ] chartMode
        - [ ] standalone
        - [ ] aws
        - [ ] gcp
        - [ ] highAvailability.replicaCount
        - [ ] highAvailability.requireAntiAffinity
        - [ ] highAvailability.certManager
        - [ ] image
        - [ ] enterpriseImage
        - [ ] logLevel
        - [ ] affinity
        - [ ] annotations.config
        - [ ] annotations.deployment
        - [ ] annotations.pod
        - [ ] annotations.service
        - [ ] extraArgs
        - [ ] extraVolumes
        - [ ] extraVolumeMounts
        - [ ] imagePullPolicy
        - [ ] initContainers
        - [ ] resources
        - [ ] tolerations
        - [ ] ---
        - [ ] teleport-kube-agent
        - [ ] roles
        - [ ] authToken
        - [ ] proxyAddr
        - [ ] kubeClusterName
        - [ ] apps
        - [ ] databases
        - [ ] teleportVersionOverride
        - [ ] insecureSkipProxyTLSVerify
        - [ ] podSecurityPolicy
        - [ ] labels
        - [ ] image
        - [ ] replicaCount
        - [ ] clusterRoleName
        - [ ] clusterRoleBindingName
        - [ ] serviceAccountName
        - [ ] secretName
        - [ ] logLevel
        - [ ] affinity
        - [ ] annotations.config
        - [ ] annotations.deployment
        - [ ] annotations.pod
        - [ ] extraVolumes
        - [ ] extraVolumeMounts
        - [ ] imagePullPolicy
        - [ ] initContainers
        - [ ] resources
        - [ ] tolerations
    - [ ] Access Controls
        - [ ] Single Sign-On and Kubernetes RBAC
        - [ ] Mapping OIDC claims and SAML attributes to Kubernetes groups
        - [ ] Local Users
        - [ ] Kubernetes labels
        - [ ] Impersonation
        - [ ] Next steps
- [ ] Database Access Section
    - [ ] Introduction
        - [ ] Database Access
        - [ ] Demo
        - [ ] Getting started
        - [ ] Guides
        - [ ] Resources
        - [ ] FAQ
        - W/ Demo video
        - W/ Tile landing
    - [ ] Getting Started
        - [ ] Getting Started
        - [ ] Step 1/3. Setup Aurora
        - [ ] Step 2/3. Setup Teleport
        - [ ] Step 3/3. Connect
        - [ ] Next steps
    - [ ] Guides
        - W/ Tile landing
        - [ ] AWS RDS/Aurora PostgresSQL
            - [ ] AWS RDS/Aurora PostgreSQL
            - [ ] Enable IAM authentication
            - [ ] Create IAM policy
            - [ ] Create a database user
            - [ ] Configure Teleport
            - [ ] Connect
        - [ ] AWS RDS/Aurora MySQL
            - [ ] AWS RDS/Aurora MySQL
            - [ ] Enable IAM authentication
            - [ ] Create IAM policy
            - [ ] Create a database user
            - [ ] Configure Teleport
            - [ ] Connect
        - [ ] AWS Redshift PostgresSQL
            - [ ] AWS Redshift PostgreSQL
            - [ ] Prerequisites
            - [ ] Create IAM policy
            - [ ] Setup Teleport Auth and Proxy services
            - [ ] Setup Teleport Database Service
            - [ ] Connect
        - [ ] GCP Cloud SQL PostgresSQL
            - [ ] GCP Cloud SQL PostgreSQL
            - [ ] Enable Cloud SQL IAM authentication
            - [ ] Create Service account for database
            - [ ] Create Service Account for Teleport Database Service
            - [ ] Gather Cloud SQL instance information
            - [ ] Setup Teleport Auth and Proxy Services
            - [ ] Setup Teleport Database Service
            - [ ] Connect
        - [ ] Self-Hosted PostgreSQL
            - [ ] Self-Hosted PostgreSQL
            - [ ] Create certificate/key pair
            - [ ] Configure PostgreSQL server
            - [ ] Configure Teleport
            - [ ] Connect
        - [ ] Self-Hosted MySQL
            - [ ] Self-Hosted MySQL
            - [ ] Create certificate/key pair
            - [ ] Configure MySQL Server
            - [ ] Configure Teleport
            - [ ] Connect
        - [ ] Database GUI Clients
            - [ ] Graphical Database Clients
            - [ ] pgAdmin 4
            - [ ] MySQL Workbench
    - [ ] Access Controls
        - [ ] Database Access Role-Based Access Control
        - [ ] Role configuration
        - [ ] Database names
        - [ ] Template variables
    - [ ] Architecture
        - [ ] Database Access Architecture
        - [ ] How it works
        - [ ] Authentication
        - [ ] Next steps
    - [ ] Reference
        - W/ Tile landing
        - [ ] Configuration
            - [ ] Getting Started
            - [ ] Step 1/3. Setup Aurora
            - [ ] Step 2/3. Setup Teleport
            - [ ] Step 3/3. Connect
            - [ ] Next steps
        - [ ] CLI
            - [ ] Database Access CLI Reference
            - [ ] teleport db start
            - [ ] tctl auth sign
            - [ ] tctl db ls
            - [ ] tsh db ls
            - [ ] tsh db login
            - [ ] tsh db logout
            - [ ] tsh db env
            - [ ] tsh db config
        - [ ] Audit Events
            - [ ] Self-Hosted MySQL
            - [ ] Create certificate/key pair
            - [ ] Configure MySQL Server
            - [ ] Configure Teleport
            - [ ] Connect
    - [ ] FAQ
        - [ ] Database Access FAQ
        - [ ] Which database protocols does Teleport Database Access support?
        - [ ] Which PostgreSQL protocol features are not supported?
        - [ ] Can database clients use public addresses that aren't their web public address?
        - [ ] Do you support database client X?
        - [ ] When will you support database X?
- [ ] Access Controls Section
    - [ ] Introduction
        - [ ] Introduction
        - [ ] Getting Started
        - [ ] Guides
        - [ ] How does it work?
        - w/ Tile landing
    - [ ] Getting Started
        - [ ] Getting Started
        - [ ] Prerequisites
        - [ ] Step 1/3. Add local users with preset roles
        - [ ] Step 2/3. Map SSO users to roles
        - [ ] Step 3/3. Create a custom role
        - [ ] Next steps
    - [ ] Guides
       - w/ Tile landing
       - [ ] Role Templates
            - [ ] Role Templates
            - [ ] Prerequisites
            - [ ] Role Templates
            - [ ] Local users
            - [ ] SSO users
            - [ ] Interpolation rules
        - [ ] Second Factor - U2F
            - [ ] U2F
            - [ ] Prerequisites
            - [ ] Enable U2F support
            - [ ] Register U2F devices as a user
            - [ ] Login using U2F
            - [ ] Next steps
        - [ ] Per-session MFA
            - [ ] Per-session MFA
            - [ ] Prerequisites
            - [ ] Configuration
            - [ ] Limitations
        - [ ] Dual Authorization
            - [ ] Dual Authorization
            - [ ] Prerequisites
            - [ ] Set up Teleport Bot
            - [ ] Dual authorization
            - [ ] Access Requests flow
            - [ ] Troubleshooting
        - [ ] Impersonation
            - [ ] Impersonation
            - [ ] Prerequisites
            - [ ] Step 1/3. Create a CI/CD user
            - [ ] Step 2/3. Create an impersonator
            - [ ] Step 3/3. Dynamic impersonation
    - [ ] Reference
        - [ ] Roles
        - [ ] RBAC for hosts
        - [ ] Teleport resources
    - [ ] FAQ
        - [ ] Access Controls FAQ
        - Section-specific FAQ
- [ ] Preview Section
    - [ ] Upcoming Releases
        - [ ] Teleport 6.2 "Buffalo"
        - [ ] Teleport 7.0 "Stockholm"
        - [ ] Teleport Cloud "Washington"
        - [ ] Semantic Versioning
- [ ] Infrastructure Guides Section
    - [ ] AWS
        - [ ] Teleport introduction
        - [ ] Setting up a High Availability Teleport cluster
        - [ ] Deploying with CloudFormation
        - [ ] Deploying with Terraform
        - [ ] Upgrading
        - [ ] Using Teleport with EKS
        - [ ] Running Teleport Enterprise on AWS
        - [ ] Teleport AWS Tips and Tricks
    - [ ] AWS Terraform
        - [ ] Prerequisites
        - [ ] Get the Terraform code
        - [ ] Set up variables
        - [ ] Reference deployment defaults
        - [ ] Deploying with Terraform
        - [ ] Accessing the cluster after Terraform setup
        - [ ] Restarting/checking Teleport services
        - [ ] Adding EC2 instances to your Teleport cluster
        - [ ] Script to quickly connect to instances
    - [ ] GCP
        - [ ] GCP Teleport introduction
        - [ ] Quickstart
        - [ ] Step 1/4. Configure Teleport Auth server
        - [ ] Step 2/4. Setup Proxy
        - [ ] Step 3/4. Setup Teleport Nodes
        - [ ] Step 4/4. Add users
        - [ ] Teleport on GCP FAQ
    - [ ] IBM
        - [ ] Teleport on IBM Cloud FAQ
        - [ ] IBM Teleport introduction
- [ ] Teleport Enterprise Section
    - [ ] Introduction
        - [ ] Role-Based Access Control
        - [ ] Single Sign-On
        - [ ] FedRAMP/FIPS
        - [ ] Access Requests
    - [ ] Quick Start Guide
        - [ ] Prerequisites
        - [ ] Step 1/3. Installing
        - [ ] Step 2/3. Start Teleport on auth.example.com
        - [ ] Step 3/3. Adding users
        - [ ] Run Teleport Enterprise using Docker
        - [ ] Troubleshooting
        - [ ] Getting help
    - [ ] Single Sign-On (SSO)
        - [ ] How does SSO work with SSH?
        - [ ] Configuring SSO
        - [ ] Working with external email identity
        - [ ] Multiple SSO Providers
        - [ ] SSO customization
        - [ ] Troubleshooting
        - Guides
            - [ ] Azure Active Directory (AD)
                - [ ] Prerequisites
                - [ ] Configure Azure AD
                - [ ] Create a SAML connector
                - [ ] Create Teleport roles
                - [ ] Testing
                - [ ] Token encryption
                - [ ] Troubleshooting
            - [ ] Active Directory (ADFS)
                - [ ] Active Directory as an SSO provider for SSH authentication
                - [ ] Enable ADFS authentication
                - [ ] Configure ADFS
                - [ ] Create Teleport roles
                - [ ] Export the signing key
                - [ ] Testing
                - [ ] Troubleshooting
            - [ ] Google Workspace
                - [ ] Google Workspace as SSO for SSH
                - [ ] Prerequisites
                - [ ] Configure G Suite
                - [ ] Create a Service Account
                - [ ] Manage API scopes
                - [ ] Create a OIDC Connector
                - [ ] Testing
                - [ ] Troubleshooting
            - [ ] GitLab
                - [ ] How to use GitLab as a single sign-on (SSO) provider with Teleport
                - [ ] Enable OIDC Authentication
                - [ ] Configure GitLab
                - [ ] Configure Teleport
                - [ ] Create Teleport Roles
                - [ ] Testing
                - [ ] Troubleshooting
            - [ ] OneLogin
                - [ ] Using OneLogin as a single sign-on (SSO) provider for SSH
                - [ ] Enable SAML Authentication
                - [ ] Configure Application
                - [ ] Create a SAML Connector
                - [ ] Create Teleport Roles
                - [ ] Testing
                - [ ] Troubleshooting
            - [ ] OIDC
                - [ ] Enable OIDC Authentication
                - [ ] Identity Providers
                - [ ] OIDC Redirect URL
                - [ ] OIDC connector configuration
                - [ ] Create Teleport Roles
                - [ ] Testing
                - [ ] Troubleshooting
            - [ ] Okta
                - [ ] How to use Okta as a single sign-on (SSO) provider for SSH
                - [ ] Enable SAML Authentication
                - [ ] Configure Okta
                - [ ] Configure the App
                - [ ] Create & Assign Groups
                - [ ] Create a SAML Connector
                - [ ] Create Teleport Roles
                - [ ] Testing
                - [ ] Troubleshooting
    - [ ] Access Requests
        - [ ] Access Requests setup
        - [ ] Adding a reason to Access Requests
        - [ ] Integrating with an external tool
        - Integration Guides
            - [ ] Integrating Teleport with Slack
                - [ ] Setup
                - [ ] Installing the Teleport Slack Plugin
                - [ ] Test run
                - [ ] Audit log
                - [ ] Feedback
            - [ ] Integrating Teleport with Mattermost
                - [ ] Setup
                - [ ] Downloading and installing the plugin
                - [ ] Audit log
                - [ ] Feedback
            - [ ] Integrating Teleport with Jira Cloud
                - [ ] Teleport Jira Plugin Setup
                - [ ] Setup
                - [ ] Setting up your Jira project
                - [ ] Installing
                - [ ] Testing
                - [ ] Audit log
                - [ ] Feedback
            - [ ] Integrating Teleport with Jira Server
                - [ ] Teleport Jira Server Plugin Setup
                - [ ] Setup
                - [ ] Installing
                - [ ] Testing
                - [ ] Audit log
                - [ ] Feedback
            - [ ] Integrating Teleport with PagerDuty
                - [ ] Teleport Pagerduty Plugin Setup
                - [ ] Setup
                - [ ] Downloading and installing the plugin
                - [ ] Audit log
                - [ ] Feedback
    - [ ] FedRAMP for SSH & K8s
        - [ ] Setup
        - [ ] Configuration
        - [ ] What else does the Teleport FIPS binary enforce?
    - [ ] Role-Based Access Control
        - Links to Access Controls Introduction
- [ ] Cloud Section
    - [ ] Introduction
        - [ ] Next steps
        - w/ Demo video
    - [ ] Getting Started
        - [ ] Step 1/3. Signup
        - [ ] Step 2/3. Install client tools
        - [ ] Step 3/3. Explore your cluster
        - [ ] Next steps
    - [ ] Architecture
        - [ ] Security
        - [ ] Compliance
        - [ ] Managed Teleport settings
        - [ ] Data retention
        - [ ] High Availability
    - [ ] Teleport Cloud FAQ
        - Section-specific FAQ
- [ ] Architecture Section
    - [ ] Architecture Overview
        - [ ] What makes Teleport different
        - [ ] Design principles
        - [ ] Definitions
        - [ ] Teleport services
        - [ ] Basic architecture overview
        - [ ] Detailed architecture overview
        - [ ] Teleport CLI tools
        - [ ] Next steps
    - [ ] Teleport Users
        - [ ] Types of users
        - [ ] User roles
        - [ ] More concepts
    - [ ] Teleport Nodes
        - [ ] The Node service
        - [ ] Node identity on a cluster
        - [ ] Connecting to Nodes
        - [ ] Cluster state
        - [ ] Session recording
        - [ ] Trusted Clusters
        - [ ] More concepts
    - [ ] Teleport Auth
        - [ ] Authentication vs. Authorization
        - [ ] SSH certificates
        - [ ] Authentication in Teleport
        - [ ] Certificate rotation
        - [ ] Auth API
        - [ ] Auth state
        - [ ] Audit log
        - [ ] Storage back-ends
        - [ ] More concepts
    - [ ] Teleport Proxy
        - [ ] Connecting to a Node
        - [ ] Recording Proxy mode
        - [ ] More concepts
    - [ ] Trusted Clusters
        - [ ] Introduction
        - [ ] Join Tokens
        - [ ] RBAC
        - [ ] Updating Trusted Cluster role map
        - [ ] Using Trusted CLusters
        - [ ] Sharing user traings between Trusted Clusters
        - [ ] How does it work?
        - [ ] Troubleshooting
- [ ] Advanced Features Section
    - [ ] Enhanced Session Recording
        - [ ] Requirements
        - [ ] Step 1/5. Check / Patch kernel
        - [ ] Step 2/5. Install BCC tools
        - [ ] Step 3/5. Install and configure Teleport Node
        - [ ] Step 4/5. Test by logging into node via Teleport
        - [ ] Step 5/5. Inspect logs
- [ ] Reference Section
    - [ ] YAML
        - [ ] teleport.yaml
    - [ ] CLI
        - [ ] teleport
        - [ ] tsh
        - [ ] tctl
    - [ ] Metrics
        - [ ] Teleport Prometheus endpoint
    - [ ] API
        - [ ] pkg.go
        - w/ Tile landing
        - [ ] Teleport API Introduction
            - [ ] Go client
            - [ ] Get started
        - [ ] Getting Started
            - [ ] Prerequisites
            - [ ] Step 1/3. Create a user
            - [ ] Step 2/3. Generate client credentials
            - [ ] Step 3/3. Create a Go project
            - [ ] Next steps
        - [ ] API Architecture
            - [ ] Authentication
            - [ ] Authorization
            - [ ] Credentials
            - [ ] Client connection