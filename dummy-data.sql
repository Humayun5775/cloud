-- Insert dummy users
INSERT INTO users (email, full_name, password_hash, role, department) VALUES
('admin@example.com', 'Admin User', '$2a$12$1234567890123456789012', 'admin', 'Administration'),
('john.doe@example.com', 'John Doe', '$2a$12$abcdefghijklmnopqrstuv', 'employee', 'Sales'),
('jane.smith@example.com', 'Jane Smith', '$2a$12$uvwxyzabcdefghijklmno', 'employee', 'Marketing'),
('bob.johnson@example.com', 'Bob Johnson', '$2a$12$pqrstuvwxyzabcdefghij', 'employee', 'Finance'),
('sarah.lee@example.com', 'Sarah Lee', '$2a$12$ghijklmnopqrstuvwxyzab', 'employee', 'HR'),
('client1@company.com', 'Client One', '$2a$12$defghijklmnopqrstuvwxy', 'client', NULL);

-- Insert groups
INSERT INTO groups (name, description) VALUES
('Sales Team', 'All members of the sales department'),
('Marketing Team', 'All members of the marketing department'),
('Finance Team', 'All members of the finance department'),
('HR Team', 'All members of the HR department'),
('Leadership', 'Company leadership and managers');

-- Insert group members
INSERT INTO group_members (group_id, user_id, role) VALUES
(1, 2, 'admin'), -- John is Sales Team admin
(2, 3, 'admin'), -- Jane is Marketing Team admin
(3, 4, 'admin'), -- Bob is Finance Team admin
(4, 5, 'admin'), -- Sarah is HR Team admin
(5, 1, 'admin'), -- Admin user is in Leadership
(5, 2, 'member'), -- John is in Leadership
(5, 3, 'member'); -- Jane is in Leadership

-- Insert clients
INSERT INTO clients (name, email, account_manager_id, company, is_business_client) VALUES
('Acme Corp', 'contact@acmecorp.com', 2, 'Acme Corporation', TRUE),
('TechStart', 'info@techstart.com', 2, 'TechStart Inc.', TRUE),
('Jane Individual', 'jane@personal.com', 3, NULL, FALSE);

-- Insert root folders for each user
-- Personal folders
INSERT INTO folders (name, owner_id, parent_folder_id, folder_type, data_classification) VALUES
('John\'s Personal', 2, NULL, 'personal', 'confidential'),
('Jane\'s Personal', 3, NULL, 'personal', 'confidential'),
('Bob\'s Personal', 4, NULL, 'personal', 'confidential'),
('Sarah\'s Personal', 5, NULL, 'personal', 'confidential');

-- Business folders
INSERT INTO folders (name, owner_id, parent_folder_id, folder_type, data_classification) VALUES
('Sales Department', 2, NULL, 'business', 'internal'),
('Marketing Department', 3, NULL, 'business', 'internal'),
('Finance Department', 4, NULL, 'business', 'restricted'),
('HR Department', 5, NULL, 'business', 'restricted');

-- Client folders
INSERT INTO folders (name, owner_id, parent_folder_id, folder_type, client_id, data_classification) VALUES
('Acme Corp', 2, NULL, 'client', 1, 'confidential'),
('TechStart', 2, NULL, 'client', 2, 'confidential'),
('Jane Individual', 3, NULL, 'client', 3, 'confidential');

-- Sub-folders
INSERT INTO folders (name, owner_id, parent_folder_id, folder_type, data_classification) VALUES
('Projects', 2, 1, 'personal', 'confidential'),
('Documents', 2, 1, 'personal', 'confidential'),
('Sales Reports', 2, 5, 'business', 'internal'),
('Contracts', 2, 5, 'business', 'restricted'),
('Marketing Campaigns', 3, 6, 'business', 'internal'),
('Design Assets', 3, 6, 'business', 'internal'),
('Financial Reports', 4, 7, 'business', 'restricted'),
('Budget Planning', 4, 7, 'business', 'restricted'),
('Employee Records', 5, 8, 'business', 'restricted'),
('Recruitment', 5, 8, 'business', 'confidential');

-- Client sub-folders
INSERT INTO folders (name, owner_id, parent_folder_id, folder_type, client_id, data_classification) VALUES
('Acme Contracts', 2, 9, 'client', 1, 'restricted'),
('Acme Projects', 2, 9, 'client', 1, 'confidential'),
('TechStart Contracts', 2, 10, 'client', 2, 'restricted'),
('TechStart Projects', 2, 10, 'client', 2, 'confidential');

-- Insert files
INSERT INTO files (name, folder_id, owner_id, file_path, file_size, file_type, data_classification) VALUES
('Personal Notes.docx', 1, 2, '/storage/personal/john/notes.docx', 256000, 'application/docx', 'confidential'),
('Sales Strategy.pptx', 5, 2, '/storage/business/sales/strategy.pptx', 1540000, 'application/pptx', 'internal'),
('Q1 Report.xlsx', 13, 4, '/storage/business/finance/q1_report.xlsx', 780000, 'application/xlsx', 'restricted'),
('Acme Contract.pdf', 17, 2, '/storage/clients/acme/contract.pdf', 450000, 'application/pdf', 'restricted'),
('Marketing Plan.docx', 6, 3, '/storage/business/marketing/plan.docx', 350000, 'application/docx', 'confidential'),
('Resume Template.docx', 16, 5, '/storage/business/hr/resume_template.docx', 125000, 'application/docx', 'internal');

-- Insert permissions
INSERT INTO permissions (resource_type, resource_id, user_id, access_level) VALUES
-- Personal folder permissions
('folder', 1, 2, 'owner'), -- John is owner of his personal folder
('folder', 2, 3, 'owner'), -- Jane is owner of her personal folder
-- Department folder permissions
('folder', 5, 2, 'owner'), -- John is owner of Sales Department
('folder', 5, 3, 'viewer'), -- Jane is viewer of Sales Department
('folder', 6, 3, 'owner'), -- Jane is owner of Marketing Department
('folder', 6, 2, 'editor'), -- John is editor of Marketing Department
('folder', 7, 4, 'owner'), -- Bob is owner of Finance Department
('folder', 8, 5, 'owner'), -- Sarah is owner of HR Department
-- Client folder permissions
('folder', 9, 2, 'owner'), -- John is owner of Acme Corp folder
('folder', 10, 2, 'owner'), -- John is owner of TechStart folder
('folder', 11, 3, 'owner'); -- Jane is owner of Jane Individual folder

-- Insert shares
INSERT INTO shares (resource_type, resource_id, shared_by, shared_with_user_id, access_level, expires_at, view_only) VALUES
('folder', 5, 2, 3, 'viewer', DATE_ADD(NOW(), INTERVAL 30 DAY), FALSE), -- John shared Sales folder with Jane
('file', 2, 2, 4, 'viewer', DATE_ADD(NOW(), INTERVAL 7 DAY), TRUE), -- John shared Sales Strategy with Bob (view only)
('folder', 6, 3, 2, 'editor', NULL, FALSE); -- Jane shared Marketing folder with John (no expiry)

-- Share with external users
INSERT INTO shares (resource_type, resource_id, shared_by, shared_with_email, access_level, share_link, password_protected, expires_at, view_only) VALUES
('file', 4, 2, 'external@acmecorp.com', 'viewer', 'abc123def456', TRUE, DATE_ADD(NOW(), INTERVAL 14 DAY), TRUE);


-- Insert audit logs (continued)
INSERT INTO audit_logs (user_id, action, resource_type, resource_id, details, ip_address) VALUES
(3, 'VIEW', 'file', 2, '{"name": "Sales Strategy.pptx"}', '192.168.1.101'),
(4, 'CREATE', 'file', 3, '{"name": "Q1 Report.xlsx", "size": 780000}', '192.168.1.102'),
(5, 'MODIFY', 'folder', 16, '{"name": "Recruitment", "previous_name": "Hiring"}', '192.168.1.103'),
(2, 'DOWNLOAD', 'file', 4, '{"name": "Acme Contract.pdf"}', '192.168.1.100'),
(3, 'SHARE', 'folder', 6, '{"shared_with": "john.doe@example.com", "access_level": "editor"}', '192.168.1.101'),
(1, 'DELETE', 'file', 10, '{"name": "Obsolete Report.pdf"}', '192.168.1.200');

-- Insert retention policies
INSERT INTO retention_policies (name, folder_type, retention_period, auto_archive, auto_delete) VALUES
('Personal Data', 'personal', 365, TRUE, FALSE),
('Business Documents', 'business', 730, TRUE, FALSE),
('Client Contracts', 'client', 2190, TRUE, FALSE), -- 6 years
('HR Records', 'business', 1825, TRUE, FALSE), -- 5 years
('Financial Records', 'business', 2555, TRUE, FALSE); -- 7 years
