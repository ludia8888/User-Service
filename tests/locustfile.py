"""
Load testing script using Locust
Tests the performance and scalability of User Service
"""
from locust import HttpUser, task, between
import random
import string
import json


def generate_random_string(length=8):
    """Generate random string for unique usernames"""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


class UserServiceLoadTest(HttpUser):
    """Load test for User Service"""
    wait_time = between(1, 3)  # Wait 1-3 seconds between tasks
    
    def on_start(self):
        """Called when a user starts"""
        # Register a unique user for this session
        self.username = f"load_test_{generate_random_string()}"
        self.email = f"{self.username}@loadtest.com"
        self.password = "LoadTest@Password123!"
        
        # Register the user
        response = self.client.post(
            "/auth/register",
            json={
                "username": self.username,
                "email": self.email,
                "password": self.password,
                "full_name": "Load Test User"
            }
        )
        
        if response.status_code == 200:
            # Login to get token
            login_response = self.client.post(
                "/auth/login",
                data={
                    "username": self.username,
                    "password": self.password
                }
            )
            
            if login_response.status_code == 200:
                data = login_response.json()
                self.token = data["access_token"]
                self.headers = {"Authorization": f"Bearer {self.token}"}
            else:
                self.token = None
                self.headers = {}
        else:
            self.token = None
            self.headers = {}
    
    @task(1)
    def health_check(self):
        """Test health endpoint"""
        self.client.get("/health")
    
    @task(2)
    def register_new_user(self):
        """Test user registration"""
        username = f"user_{generate_random_string()}"
        self.client.post(
            "/auth/register",
            json={
                "username": username,
                "email": f"{username}@test.com",
                "password": "Test@Password123!",
                "full_name": "Test User"
            },
            catch_response=True
        )
    
    @task(5)
    def login(self):
        """Test login endpoint"""
        if self.username and self.password:
            self.client.post(
                "/auth/login",
                data={
                    "username": self.username,
                    "password": self.password
                }
            )
    
    @task(3)
    def get_user_info(self):
        """Test get user info endpoint"""
        if self.token:
            self.client.get(
                "/auth/me",
                headers=self.headers
            )
    
    @task(1)
    def refresh_token(self):
        """Test token refresh"""
        if hasattr(self, 'refresh_token'):
            self.client.post(
                "/auth/refresh",
                json={"refresh_token": self.refresh_token}
            )
    
    @task(1)
    def change_password(self):
        """Test password change"""
        if self.token:
            new_password = f"NewPass@{generate_random_string()}!"
            response = self.client.post(
                "/auth/change-password",
                headers=self.headers,
                json={
                    "current_password": self.password,
                    "new_password": new_password
                }
            )
            if response.status_code == 200:
                self.password = new_password


class AdminUserLoadTest(HttpUser):
    """Load test simulating admin users"""
    wait_time = between(2, 5)
    
    def on_start(self):
        """Setup admin user session"""
        # In real scenario, this would use pre-created admin credentials
        self.admin_token = None
        self.headers = {}
    
    @task(1)
    def list_users(self):
        """Test user listing (admin endpoint)"""
        if self.admin_token:
            self.client.get(
                "/api/v1/users",
                headers=self.headers,
                params={
                    "page": 1,
                    "per_page": 10
                }
            )
    
    @task(1)
    def search_users(self):
        """Test user search"""
        if self.admin_token:
            self.client.get(
                "/api/v1/users/search",
                headers=self.headers,
                params={
                    "query": "test",
                    "limit": 10
                }
            )


class RateLimitTest(HttpUser):
    """Test rate limiting behavior"""
    wait_time = between(0.1, 0.5)  # Very fast requests
    
    @task
    def rapid_requests(self):
        """Make rapid requests to test rate limiting"""
        # Target the login endpoint which has rate limiting
        self.client.post(
            "/auth/login",
            data={
                "username": "nonexistent",
                "password": "doesntmatter"
            },
            catch_response=True
        )