import requests

BASE_URL = "http://127.0.0.1:8000"  # Adjust if your FastAPI app runs on a different host or port

# Test 1: Sign up a new user
def test_signup():
    url = f"{BASE_URL}/signup"
    payload = {
        "username": "testuser3",
        "password": "testpassword"
    }
    
    response = requests.post(url, json=payload)
    
    assert response.status_code == 200
    print("Signup Response:", response.json())
    
# Test 2: Log in and receive a JWT token
def test_login():
    url = f"{BASE_URL}/login"
    payload = {
        "username": "testuser3",
        "password": "testpassword"
    }
    
    response = requests.post(url, json=payload)
    
    assert response.status_code == 200
    print("Login Response:", response.json())
    return response.json()["session_token"]  # Return the access token

# Test 3: Validate the JWT token
def test_validate_token(token: str):
    url = f"{BASE_URL}/validate_token"
    payload = {
        "token": token
    }
    
    response = requests.post(url, json=payload)
    
    assert response.status_code == 200
    print("Validate Token Response:", response.json())

# Run tests
if __name__ == "__main__":
    print("Testing Sign Up...")
    # test_signup()
    
    print("Testing Login...")
    token = test_login()
    
    print("Testing Token Validation...")
    test_validate_token(token)
