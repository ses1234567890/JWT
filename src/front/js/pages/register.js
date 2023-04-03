import React, { useState } from "react";
import { useNavigate } from "react-router-dom";

export const Register = () => {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  const sendRegisterCredential = async () => {
    const response = await fetch(process.env.BACKEND_URL + "/api/register", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        email: email,
        password: password,
      }),
    });
    const data = await response.json();
    if (response.ok) {
      navigate("/");
    } else {
      setError(data.response);
    }
  };

  return (
    <div className="container col-6 mt-3 border rounded">
      <h2 className="text-center m-3">Register</h2>
      <div className="row my-3">
        <label className="col-sm-2 col-form-label" htmlFor="email">
          Email:{" "}
        </label>
        <div className="col-sm-10">
          <input
            className="form-control"
            name="email"
            type="email"
            placeholder="Email"
            value={email}
            onChange={(e) => {
              setError(false);
              setEmail(e.target.value);
            }}
          ></input>
        </div>
      </div>
      <div className="row my-3">
        <label className="col-sm-2 col-form-label" htmlFor="password">
          Password:{" "}
        </label>
        <div className="col-sm-10">
          <input
            className="form-control"
            name="password"
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => {
              setError(false);
              setPassword(e.target.value);
            }}
          ></input>
        </div>
      </div>
      <div className="text-center mt-2 p-3 ">
        <button
          className="btn btn-success btn-lg"
          onClick={() => {
            sendRegisterCredential();
          }}
        >
          Register
        </button>
        {error ? <p className="alert alert-warning mt-2">{error}</p> : null}
      </div>
    </div>
  );
};
