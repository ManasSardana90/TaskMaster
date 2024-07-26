# TaskMaster - To-Do List Application

TaskMaster is a simple and secure to-do list application built with React and Node.js. Users can register, log in, and manage their tasks. It supports OAuth authentication using Google and GitHub.

## Features

- User registration and login
- OAuth login with Google and GitHub
- Create, read, update, and delete (CRUD) operations for to-do tasks
- Task completion tracking
- Secure JWT-based authentication
- Input validation and error handling
- Responsive design

## Technologies Used

- Frontend: React, Axios, FontAwesome
- Backend: Node.js, Express, Mongoose, Passport, JWT
- Database: MongoDB (MongoDB Atlas)
- Security: Helmet, express-rate-limit

## Installation

### Prerequisites

- Node.js (v14.x or higher)
- npm (v6.x or higher)
- MongoDB Atlas account

### Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/taskmaster.git
   cd taskmaster
   ```

2. Install dependencies for both backend and frontend:

   ```bash
   # Navigate to the backend directory
   cd backend
   npm install

   # Navigate to the frontend directory
   cd ../todo-app
   npm install
   ```

3. Create a `.env` file in the `backend` directory and add your configuration details:

   ```env
   MONGO_URI=mongodb+srv://<username>:<password>@cluster0.mongodb.net/todoapp?retryWrites=true&w=majority
   GOOGLE_CLIENT_ID=your_google_client_id
   GOOGLE_CLIENT_SECRET=your_google_client_secret
   GITHUB_CLIENT_ID=your_github_client_id
   GITHUB_CLIENT_SECRET=your_github_client_secret
   JWT_SECRET=your_jwt_secret
   SESSION_SECRET=your_session_secret
   ```

### Running the Application

1. Start the backend server:

   ```bash
   cd backend
   node server.js
   ```

2. Start the frontend development server:

   ```bash
   cd ../todo-app
   npm start
   ```

3. Open your browser and navigate to `http://localhost:3000`.

## Project Structure

- `backend/`: Contains the backend Node.js application
  - `server.js`: The main server file
- `todo-app/`: Contains the frontend React application
  - `src/App.js`: The main React component
  - `src/App.css`: The main CSS file for styling

## Usage

### Register

1. Open the application in your browser.
2. Fill in the username and password fields and click "Register".
3. If successful, you will see a confirmation message.

### Login

1. Open the application in your browser.
2. Fill in the username and password fields and click "Login".
3. Alternatively, you can log in using Google or GitHub by clicking the respective buttons.

### Managing Tasks

1. After logging in, you can add tasks by typing in the input field and clicking "Add".
2. You can mark tasks as completed by clicking the checkbox next to the task.
3. You can delete tasks by clicking the trash icon next to the task.

## Security Measures

- Helmet is used to set various HTTP headers for security.
- express-rate-limit is used to limit repeated requests to public APIs and/or endpoints.
- Input validation and sanitization are performed using express-validator.

## Packages Used

### Frontend

- `react`: JavaScript library for building user interfaces
- `axios`: Promise-based HTTP client for the browser and Node.js
- `@fortawesome/react-fontawesome`: FontAwesome integration for React
- `@fortawesome/free-solid-svg-icons`: FontAwesome solid style icons
- `@fortawesome/fontawesome-svg-core`: FontAwesome core package
- `@fortawesome/free-brands-svg-icons`: FontAwesome brand icons

### Backend

- `express`: Fast, unopinionated, minimalist web framework for Node.js
- `mongoose`: MongoDB object modeling tool designed to work in an asynchronous environment
- `cors`: Express middleware to enable CORS with various options
- `bcryptjs`: Library to hash passwords
- `jsonwebtoken`: JSON Web Token implementation
- `passport`: Simple, unobtrusive authentication for Node.js
- `passport-google-oauth20`: Google authentication strategy for Passport
- `passport-github2`: GitHub authentication strategy for Passport
- `express-session`: Simple session middleware for Express
- `dotenv`: Module to load environment variables from a .env file
- `helmet`: Helps secure Express apps by setting various HTTP headers
- `express-rate-limit`: Basic rate-limiting middleware for Express
- `express-validator`: Set of express.js middlewares that wraps validator.js validator and sanitizer functions
