import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faTrash, faSignOutAlt } from '@fortawesome/free-solid-svg-icons';
import { faGoogle, faGithub } from '@fortawesome/free-brands-svg-icons';
import './App.css';

const API_BASE_URL = 'https://taskmaster-b766.onrender.com';

const App = () => {
  const [todos, setTodos] = useState([]);
  const [text, setText] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [token, setToken] = useState('');
  const [error, setError] = useState(null);

  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const jwtToken = urlParams.get('token');
    if (jwtToken) {
      setToken(jwtToken);
      window.history.replaceState(null, null, '/'); // Clean the URL
    }
  }, []);

  useEffect(() => {
    const fetchTodos = async () => {
      try {
        const response = await axios.get(`${API_BASE_URL}/todos`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        setTodos(response.data);
      } catch (err) {
        setError('Could not fetch todos. Please try again later.');
      }
    };

    if (token) {
      fetchTodos();
    }
  }, [token]);

  const register = async () => {
    if (!username || !password) {
      setError('Username and password are required');
      return;
    }
    try {
      await axios.post(`${API_BASE_URL}/register`, { username, password });
      setError(null);
    } catch (err) {
      if (err.response && err.response.data.errors) {
        setError(err.response.data.errors[0].msg);
      } else {
        setError('Could not register. Please try again later.');
      }
    }
  };

  const login = async () => {
    if (!username || !password) {
      setError('Username and password are required');
      return;
    }
    try {
      const response = await axios.post(`${API_BASE_URL}/login`, { username, password });
      setToken(response.data.token);
      setError(null);
    } catch (err) {
      if (err.response && err.response.data.errors) {
        setError(err.response.data.errors[0].msg);
      } else {
        setError('Could not login. Please try again later.');
      }
    }
  };

  const logout = () => {
    setToken('');
    setTodos([]);
    setText('');
    setUsername('');
    setPassword('');
    setError(null);
  };

  const addTodo = async () => {
    if (text.trim() === '') {
      setError('Text is required');
      return;
    }
    try {
      const response = await axios.post(`${API_BASE_URL}/todos`, { text }, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setTodos([...todos, response.data]);
      setText('');
      setError(null);
    } catch (err) {
      setError('Could not add todo. Please try again later.');
    }
  };

  const toggleTodo = async (id) => {
    try {
      const response = await axios.put(`${API_BASE_URL}/todos/${id}`, {}, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setTodos(todos.map(todo => todo._id === id ? response.data : todo));
      setError(null);
    } catch (err) {
      setError('Could not update todo. Please try again later.');
    }
  };

  const deleteTodo = async (id) => {
    try {
      await axios.delete(`${API_BASE_URL}/todos/${id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setTodos(todos.filter(todo => todo._id !== id));
      setError(null);
    } catch (err) {
      setError('Could not delete todo. Please try again later.');
    }
  };

  if (!token) {
    return (
      <div className="login-container">
        <h1 className="title"><img src="/logo.png" alt="TaskMaster Logo" className="logo"/>
        TaskMaster
        </h1>
        <div className="login-form">
          <h2>Login</h2>
          {error && <p style={{ color: 'red' }}>{error}</p>}
          <input
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <div className="button-container">
            <button onClick={login}>Login</button>
            <button onClick={register}>Register</button>
          </div>
          <div className="oauth-container">
            <a href={`${API_BASE_URL}/auth/google`} className="oauth-button google">
              <FontAwesomeIcon icon={faGoogle} /> Login with Google
            </a>
            <a href={`${API_BASE_URL}/auth/github`} className="oauth-button github">
              <FontAwesomeIcon icon={faGithub} /> Login with GitHub
            </a>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="app-container">
      <header>
        <h1>To-Do List</h1>
        <button className="logout-button" onClick={logout}>
          <FontAwesomeIcon icon={faSignOutAlt} /> Logout
        </button>
      </header>
      {error && <p style={{ color: 'red' }}>{error}</p>}
      <div className="input-container">
        <input
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Add a new task"
        />
        <button onClick={addTodo}>Add</button>
      </div>
      <ul className="todo-list">
        {todos.map(todo => (
          <li key={todo._id} className="todo-item">
            <span
              onClick={() => toggleTodo(todo._id)}
              className={todo.completed ? 'completed' : ''}
            >
              <input
                type="checkbox"
                checked={todo.completed}
                onChange={() => toggleTodo(todo._id)}
              />
              {todo.text}
            </span>
            <button className="delete-button" onClick={() => deleteTodo(todo._id)}>
              <FontAwesomeIcon icon={faTrash} />
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
};

export default App;
