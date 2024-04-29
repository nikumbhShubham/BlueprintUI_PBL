import React from 'react'

import { Helmet } from 'react-helmet'

import WorkspaceHeader from '../components/workspace-header'
import WorkspaceSidebar from '../components/workspace-sidebar'
import './my-project.css'

const MyProject = (props) => {
  return (
    <div className="my-project-container">
      <Helmet>
        <title>My-project - Far Off Popular Locust</title>
        <meta
          property="og:title"
          content="My-project - Far Off Popular Locust"
        />
      </Helmet>
      <WorkspaceHeader rootClassName="workspace-header-root-class-name5"></WorkspaceHeader>
      <div className="my-project-container1">
        <WorkspaceSidebar rootClassName="workspace-sidebar-root-class-name3"></WorkspaceSidebar>
        <div className="my-project-container2">
          <div className="my-project-container3">
            <div className="my-project-feature-card button">
              <img
                alt="image"
                src="https://play.teleporthq.io/static/svg/default-img.svg"
                className="my-project-image"
              />
              <span className="my-project-text">Project 1</span>
              <span className="my-project-text01">500+ items sold</span>
            </div>
            <div className="my-project-feature-card1 button">
              <img
                alt="image"
                src="https://play.teleporthq.io/static/svg/default-img.svg"
                className="my-project-image1"
              />
              <span className="my-project-text02">
                <span>Project 2</span>
                <br></br>
              </span>
              <span className="my-project-text05">500+ items sold</span>
            </div>
            <div className="my-project-feature-card2 button">
              <img
                alt="image"
                src="https://play.teleporthq.io/static/svg/default-img.svg"
                className="my-project-image2"
              />
              <span className="my-project-text06">Project 3</span>
              <span className="my-project-text07">500+ items sold</span>
            </div>
            <div className="my-project-feature-card3 button">
              <img
                alt="image"
                src="https://play.teleporthq.io/static/svg/default-img.svg"
                className="my-project-image3"
              />
              <span className="my-project-text08">Project 4</span>
              <span className="my-project-text09">500+ items sold</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default MyProject
