import React, { useState } from "react";
import axios from "axios";
import "./App.css";

function App() {
  const [isSignup, setIsSignup] = useState(false);
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    password: ""
  });

  const toggleForm = () => {
    setIsSignup(!isSignup);
    setFormData({ name: "", email: "", password: "" }); // Clear form data
  };

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSignup = async () => {
    try {
      const response = await axios.post('http://localhost:3001/signup', {
        name: formData.name,
        email: formData.email,
        password: formData.password
      });
      alert(response.data.message);
    } catch (error) {
      alert(error.response.data.error);
    }
  };

  const handleLogin = async () => {
    try {
      const response = await axios.post('http://localhost:3001/login', {
        email: formData.email,
        password: formData.password
      });
      alert(response.data.message);
      // You can store the JWT token in localStorage if needed
      // localStorage.setItem("token", response.data.token);
    } catch (error) {
      alert(error.response.data.error);
    }
  };

  return (
    <div className={`cont ${isSignup ? "s--signup" : ""}`}>
      <div className="form sign-in">
        <h2>Welcome</h2>
        <label>
          <span>Email</span>
          <input type="email" name="email" value={formData.email} onChange={handleChange} />
        </label>
        <label>
          <span>Password</span>
          <input type="password" name="password" value={formData.password} onChange={handleChange} />
        </label>
        <button type="button" className="submit" onClick={handleLogin}>
          Sign In
        </button>
      </div>

      <div className="sub-cont">
        <div className="img">
          <div className="img__text m--up">
            <h3>Don't have an account? Please Sign up!</h3>
          </div>
          <div className="img__text m--in">
            <h3>If you already have an account, just sign in.</h3>
          </div>
          <div className="img__btn" onClick={toggleForm}>
            <span className="m--up">Sign Up</span>
            <span className="m--in">Sign In</span>
          </div>
        </div>

        <div className="form sign-up">
          <h2>Create your Account</h2>
          <label>
            <span>Name</span>
            <input type="text" name="name" value={formData.name} onChange={handleChange} />
          </label>
          <label>
            <span>Email</span>
            <input type="email" name="email" value={formData.email} onChange={handleChange} />
          </label>
          <label>
            <span>Password</span>
            <input type="password" name="password" value={formData.password} onChange={handleChange} />
          </label>
          <button type="button" className="submit" onClick={handleSignup}>
            Sign Up
          </button>
        </div>
      </div>
    </div>
  );
}

export default App;
