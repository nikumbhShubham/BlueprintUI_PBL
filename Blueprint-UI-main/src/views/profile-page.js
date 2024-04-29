import React from 'react'

import { Helmet } from 'react-helmet'

import BlueprintHeader from '../components/blueprint-header'
import Sidebar from '../components/sidebar'
import Component1 from '../components/component1'
import ProfileComp from '../components/profile-comp'
import Footer from '../components/footer'
import './profile-page.css'

const ProfilePage = (props) => {
  return (
    <div className="profile-page-container">
      <Helmet>
        <title>Profile-Page - Far Off Popular Locust</title>
        <meta
          property="og:title"
          content="Profile-Page - Far Off Popular Locust"
        />
      </Helmet>
      <BlueprintHeader rootClassName="blueprint-header-root-class-name3"></BlueprintHeader>
      <div className="profile-page-container1">
        <Sidebar rootClassName="sidebar-root-class-name"></Sidebar>
        <div className="profile-page-container2">
          <div className="profile-page-container3">
            <Component1 rootClassName="component1-root-class-name"></Component1>
            <span className="profile-page-text">
              <span>Username</span>
              <br></br>
            </span>
          </div>
          <ProfileComp rootClassName="profile-comp-root-class-name"></ProfileComp>
        </div>
      </div>
      <Footer rootClassName="footer-root-class-name1"></Footer>
    </div>
  )
}

export default ProfilePage
