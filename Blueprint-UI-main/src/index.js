import React from 'react'
import ReactDOM from 'react-dom'
import {
  BrowserRouter as Router,
  Route,
  Switch,
  Redirect,
} from 'react-router-dom'

import './style.css'
import AboutUs from './views/about-us'
import ProfilePage from './views/profile-page'
import MyProject from './views/my-project'
import CreatePackage from './views/create-package'
import Login from './views/login'
import Docs from './views/docs'
import Component from './views/component'
import EditProfile from './views/edit-profile'
import UIPackages from './views/ui-packages'
import Workspace from './views/workspace'
import Home from './views/home'
import SignUp from './views/sign-up'
import NotFound from './views/not-found'

const App = () => {
  return (
    <Router>
      <Switch>
        <Route component={AboutUs} exact path="/about-us" />
        <Route component={ProfilePage} exact path="/profile-page" />
        <Route component={MyProject} exact path="/my-project" />
        <Route component={CreatePackage} exact path="/create-package" />
        <Route component={Login} exact path="/login" />
        <Route component={Docs} exact path="/docs" />
        <Route component={Component} exact path="/component" />
        <Route component={EditProfile} exact path="/edit-profile" />
        <Route component={UIPackages} exact path="/ui-packages" />
        <Route component={Workspace} exact path="/workspace" />
        <Route component={Home} exact path="/" />
        <Route component={SignUp} exact path="/sign-up" />
        <Route component={NotFound} path="**" />
        <Redirect to="**" />
      </Switch>
    </Router>
  )
}

ReactDOM.render(<App />, document.getElementById('app'))
