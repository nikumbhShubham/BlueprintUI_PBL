import React from 'react'

import { Helmet } from 'react-helmet'

import WorkspaceHeader from '../components/workspace-header'
import WorkspaceSidebar from '../components/workspace-sidebar'
import FeatureCard from '../components/feature-card'
import './workspace.css'

const Workspace = (props) => {
  return (
    <div className="workspace-container">
      <Helmet>
        <title>Workspace - Far Off Popular Locust</title>
        <meta
          property="og:title"
          content="Workspace - Far Off Popular Locust"
        />
      </Helmet>
      <WorkspaceHeader rootClassName="workspace-header-root-class-name3"></WorkspaceHeader>
      <div className="workspace-container1">
        <WorkspaceSidebar rootClassName="workspace-sidebar-root-class-name1"></WorkspaceSidebar>
        <div className="workspace-container2">
          <div className="workspace-container3">
            <FeatureCard rootClassName="feature-card-root-class-name3"></FeatureCard>
          </div>
          <div className="workspace-container4">
            <div className="workspace-feature-card button">
              <img
                alt="image"
                src="https://play.teleporthq.io/static/svg/default-img.svg"
                className="workspace-image"
              />
              <span className="workspace-text">Footer</span>
              <span className="workspace-text01">500+ items sold</span>
            </div>
            <div className="workspace-feature-card1 button">
              <img
                alt="image"
                src="https://play.teleporthq.io/static/svg/default-img.svg"
                className="workspace-image1"
              />
              <span className="workspace-text02">Footer</span>
              <span className="workspace-text03">500+ items sold</span>
            </div>
            <div className="workspace-feature-card2 button">
              <img
                alt="image"
                src="https://play.teleporthq.io/static/svg/default-img.svg"
                className="workspace-image2"
              />
              <span className="workspace-text04">Footer</span>
              <span className="workspace-text05">500+ items sold</span>
            </div>
            <div className="workspace-feature-card3 button">
              <img
                alt="image"
                src="https://play.teleporthq.io/static/svg/default-img.svg"
                className="workspace-image3"
              />
              <span className="workspace-text06">Footer</span>
              <span className="workspace-text07">500+ items sold</span>
            </div>
          </div>
          <div className="workspace-container5">
            <div className="workspace-feature-card4 button">
              <img
                alt="image"
                src="https://play.teleporthq.io/static/svg/default-img.svg"
                className="workspace-image4"
              />
              <span className="workspace-text08">Footer</span>
              <span className="workspace-text09">500+ items sold</span>
            </div>
            <div className="workspace-feature-card5 button">
              <img
                alt="image"
                src="https://play.teleporthq.io/static/svg/default-img.svg"
                className="workspace-image5"
              />
              <span className="workspace-text10">Footer</span>
              <span className="workspace-text11">500+ items sold</span>
            </div>
            <div className="workspace-feature-card6 button">
              <img
                alt="image"
                src="https://play.teleporthq.io/static/svg/default-img.svg"
                className="workspace-image6"
              />
              <span className="workspace-text12">Footer</span>
              <span className="workspace-text13">500+ items sold</span>
            </div>
            <div className="workspace-feature-card7 button">
              <img
                alt="image"
                src="https://play.teleporthq.io/static/svg/default-img.svg"
                className="workspace-image7"
              />
              <span className="workspace-text14">Footer</span>
              <span className="workspace-text15">500+ items sold</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Workspace
