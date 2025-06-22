# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for the readonly enforcement in Aurora DSQL MCP Server."""

import sys
import os

# Add the parent directory to the path so we can import the modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from awslabs.aurora_dsql_mcp_server.mutable_sql_detector import (
    check_sql_injection_risk,
    detect_mutating_keywords,
    detect_transaction_bypass_attempt,
)


class TestReadonlyEnforcement:
    """Test cases for the readonly enforcement mechanisms."""

    def test_detect_transaction_bypass_complex_query(self):
        """Test detection of complex queries that attempt to bypass readonly restrictions."""
        # Test a complex query that combines multiple statements
        complex_sql = "SELECT * FROM information_schema.tables; COMMIT; BEGIN; CREATE TABLE test_table (id int)"

        # Should detect transaction bypass attempt
        assert detect_transaction_bypass_attempt(complex_sql) is True

        # Should also detect mutating keywords
        mutating_keywords = detect_mutating_keywords(complex_sql)
        assert 'CREATE' in mutating_keywords

    def test_detect_mutating_keywords_create_table(self):
        """Test detection of CREATE TABLE statements."""
        sql = "CREATE TABLE test_table (id int, name varchar(50))"
        keywords = detect_mutating_keywords(sql)
        assert 'CREATE' in keywords
        assert 'DDL' in keywords

    def test_detect_mutating_keywords_insert(self):
        """Test detection of INSERT statements."""
        sql = "INSERT INTO users (name, email) VALUES ('test', 'test@example.com')"
        keywords = detect_mutating_keywords(sql)
        assert 'INSERT' in keywords

    def test_detect_mutating_keywords_update(self):
        """Test detection of UPDATE statements."""
        sql = "UPDATE users SET name = 'updated' WHERE id = 1"
        keywords = detect_mutating_keywords(sql)
        assert 'UPDATE' in keywords

    def test_detect_mutating_keywords_delete(self):
        """Test detection of DELETE statements."""
        sql = "DELETE FROM users WHERE id = 1"
        keywords = detect_mutating_keywords(sql)
        assert 'DELETE' in keywords

    def test_detect_mutating_keywords_drop(self):
        """Test detection of DROP statements."""
        sql = "DROP TABLE users"
        keywords = detect_mutating_keywords(sql)
        assert 'DROP' in keywords
        assert 'DDL' in keywords

    def test_safe_select_queries(self):
        """Test that safe SELECT queries don't trigger security checks."""
        safe_queries = [
            "SELECT * FROM users",
            "SELECT id, name FROM users WHERE active = true",
            "SELECT COUNT(*) FROM orders",
            "SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id",
            "WITH recent_orders AS (SELECT * FROM orders WHERE created_at > '2023-01-01') SELECT * FROM recent_orders",
        ]

        for sql in safe_queries:
            # Should not detect mutating keywords
            assert detect_mutating_keywords(sql) == []

            # Should not detect injection risks
            assert check_sql_injection_risk(sql) == []

            # Should not detect transaction bypass attempts
            assert detect_transaction_bypass_attempt(sql) is False

    def test_sql_injection_patterns(self):
        """Test detection of various SQL injection patterns."""
        injection_patterns = [
            "SELECT * FROM users WHERE id = 1 OR 1=1",
            "SELECT * FROM users WHERE name = 'test' OR 'a'='a'",
            "SELECT * FROM users; DROP TABLE users; --",
            "SELECT * FROM users UNION SELECT * FROM admin_users",
            "SELECT * FROM users WHERE id = 1; INSERT INTO logs VALUES ('hacked')",
        ]

        for sql in injection_patterns:
            issues = check_sql_injection_risk(sql)
            assert len(issues) > 0, f"Should detect injection risk in: {sql}"

    def test_transaction_bypass_variations(self):
        """Test detection of various transaction bypass attempts."""
        bypass_attempts = [
            "SELECT 1; COMMIT; CREATE TABLE hack (id int)",
            "SELECT * FROM users; COMMIT; BEGIN; DROP TABLE sensitive_data",
            "SELECT COUNT(*); ROLLBACK; INSERT INTO logs VALUES ('bypass')",
            "SELECT name FROM users; COMMIT; ALTER TABLE users ADD COLUMN hacked boolean",
        ]

        for sql in bypass_attempts:
            assert detect_transaction_bypass_attempt(sql) is True, f"Should detect bypass in: {sql}"

    def test_permission_statements(self):
        """Test detection of permission-related statements."""
        permission_sql = [
            "GRANT ALL PRIVILEGES ON database.* TO 'user'@'host'",
            "REVOKE SELECT ON table FROM user",
            "CREATE USER 'newuser'@'localhost' IDENTIFIED BY 'password'",
            "DROP USER 'olduser'@'localhost'",
        ]

        for sql in permission_sql:
            keywords = detect_mutating_keywords(sql)
            assert 'PERMISSION' in keywords, f"Should detect permission keywords in: {sql}"

    def test_system_statements(self):
        """Test detection of system-level statements."""
        system_sql = [
            "SET GLOBAL max_connections = 1000",
            "FLUSH PRIVILEGES",
            "LOAD DATA INFILE '/tmp/data.csv' INTO TABLE users",
            "SELECT * INTO OUTFILE '/tmp/output.txt' FROM users",
        ]

        for sql in system_sql:
            keywords = detect_mutating_keywords(sql)
            assert 'SYSTEM' in keywords, f"Should detect system keywords in: {sql}"

    def test_case_insensitive_detection(self):
        """Test that detection works regardless of case."""
        variations = [
            "create table test (id int)",
            "CREATE TABLE test (id int)",
            "Create Table test (id int)",
            "CrEaTe TaBlE test (id int)",
        ]

        for sql in variations:
            keywords = detect_mutating_keywords(sql)
            assert 'CREATE' in keywords, f"Should detect CREATE regardless of case in: {sql}"
            assert 'DDL' in keywords, f"Should detect DDL regardless of case in: {sql}"

    def test_postgresql_specific_patterns(self):
        """Test detection of PostgreSQL-specific patterns."""
        postgres_sql = [
            "COPY users FROM '/tmp/users.csv'",
            "COPY (SELECT * FROM users) TO '/tmp/export.csv'",
            "SELECT pg_sleep(5)",
        ]

        for sql in postgres_sql:
            # Should detect either mutating keywords or injection risks
            has_mutating = len(detect_mutating_keywords(sql)) > 0
            has_injection = len(check_sql_injection_risk(sql)) > 0
            assert has_mutating or has_injection, f"Should detect security issue in: {sql}"

    def test_comment_handling(self):
        """Test that comments don't interfere with detection."""
        sql_with_comments = [
            "SELECT * FROM users; -- This is a comment\nCOMMIT; CREATE TABLE hack (id int)",
            "/* Multi-line comment */ SELECT 1; COMMIT; DROP TABLE users",
        ]

        for sql in sql_with_comments:
            assert detect_transaction_bypass_attempt(sql) is True, f"Should detect bypass despite comments in: {sql}"
