import React from 'react'

import { Helmet } from 'react-helmet'

import BlueprintHeader from '../components/blueprint-header'
import Sidebar from '../components/sidebar'
import Component1 from '../components/component1'
import ProfileEditComp from '../components/profile-edit-comp'
import Footer from '../components/footer'
import './edit-profile.css'

const EditProfile = (props) => {
  return (
    <div className="edit-profile-container">
      <Helmet>
        <title>Edit-Profile - Far Off Popular Locust</title>
        <meta
          property="og:title"
          content="Edit-Profile - Far Off Popular Locust"
        />
      </Helmet>
      <BlueprintHeader rootClassName="blueprint-header-root-class-name5"></BlueprintHeader>
      <div className="edit-profile-container1">
        <Sidebar rootClassName="sidebar-root-class-name1"></Sidebar>
        <div className="edit-profile-container2">
          <div className="edit-profile-container3">
            <div className="edit-profile-container4">
              <Component1 rootClassName="component1-root-class-name1"></Component1>
              <span className="edit-profile-text">
                <span>Username</span>
                <br></br>
              </span>
            </div>
          </div>
          <ProfileEditComp rootClassName="profile-edit-comp-root-class-name"></ProfileEditComp>
        </div>
      </div>
      <Footer rootClassName="footer-root-class-name2"></Footer>
    </div>
  )
}

export default EditProfile
