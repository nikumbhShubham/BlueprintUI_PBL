import React from 'react'

import { Helmet } from 'react-helmet'

import WorkspaceHeader from '../components/workspace-header'
import WorkspaceSidebar from '../components/workspace-sidebar'
import './component.css'

const AppComponent = (props) => {
  return (
    <div className="app-component-container">
      <Helmet>
        <title>Component - Far Off Popular Locust</title>
        <meta
          property="og:title"
          content="Component - Far Off Popular Locust"
        />
      </Helmet>
      <WorkspaceHeader rootClassName="workspace-header-root-class-name4"></WorkspaceHeader>
      <div className="app-component-container1">
        <WorkspaceSidebar rootClassName="workspace-sidebar-root-class-name2"></WorkspaceSidebar>
        <div className="app-component-container2">
          <div className="app-component-container3">
            <div className="app-component-feature-card button">
              <img
                alt="image"
                src="https://play.teleporthq.io/static/svg/default-img.svg"
                className="app-component-image"
              />
              <span className="app-component-text">Footer</span>
              <span className="app-component-text01">500+ items sold</span>
            </div>
            <div className="app-component-feature-card01 button">
              <img
                alt="image"
                src="https://play.teleporthq.io/static/svg/default-img.svg"
                className="app-component-image01"
              />
              <span className="app-component-text02">Footer</span>
              <span className="app-component-text03">500+ items sold</span>
            </div>
            <div className="app-component-feature-card02 button">
              <img
                alt="image"
                src="https://play.teleporthq.io/static/svg/default-img.svg"
                className="app-component-image02"
              />
              <span className="app-component-text04">Footer</span>
              <span className="app-component-text05">500+ items sold</span>
            </div>
            <div className="app-component-feature-card03 button">
              <img
                alt="image"
                src="https://play.teleporthq.io/static/svg/default-img.svg"
                className="app-component-image03"
              />
              <span className="app-component-text06">Footer</span>
              <span className="app-component-text07">500+ items sold</span>
            </div>
          </div>
          <div className="app-component-container4">
            <div className="app-component-feature-card04 button">
              <img
                alt="image"
                src="https://play.teleporthq.io/static/svg/default-img.svg"
                className="app-component-image04"
              />
              <span className="app-component-text08">Footer</span>
              <span className="app-component-text09">500+ items sold</span>
            </div>
            <div className="app-component-feature-card05 button">
              <img
                alt="image"
                src="https://play.teleporthq.io/static/svg/default-img.svg"
                className="app-component-image05"
              />
              <span className="app-component-text10">Footer</span>
              <span className="app-component-text11">500+ items sold</span>
            </div>
            <div className="app-component-feature-card06 button">
              <img
                alt="image"
                src="https://play.teleporthq.io/static/svg/default-img.svg"
                className="app-component-image06"
              />
              <span className="app-component-text12">Footer</span>
              <span className="app-component-text13">500+ items sold</span>
            </div>
            <div className="app-component-feature-card07 button">
              <img
                alt="image"
                src="https://play.teleporthq.io/static/svg/default-img.svg"
                className="app-component-image07"
              />
              <span className="app-component-text14">Footer</span>
              <span className="app-component-text15">500+ items sold</span>
            </div>
          </div>
          <div className="app-component-container5">
            <div className="app-component-feature-card08 button">
              <img
                alt="image"
                src="https://play.teleporthq.io/static/svg/default-img.svg"
                className="app-component-image08"
              />
              <span className="app-component-text16">Footer</span>
              <span className="app-component-text17">500+ items sold</span>
            </div>
            <div className="app-component-feature-card09 button">
              <img
                alt="image"
                src="https://play.teleporthq.io/static/svg/default-img.svg"
                className="app-component-image09"
              />
              <span className="app-component-text18">Footer</span>
              <span className="app-component-text19">500+ items sold</span>
            </div>
            <div className="app-component-feature-card10 button">
              <img
                alt="image"
                src="https://play.teleporthq.io/static/svg/default-img.svg"
                className="app-component-image10"
              />
              <span className="app-component-text20">Footer</span>
              <span className="app-component-text21">500+ items sold</span>
            </div>
            <div className="app-component-feature-card11 button">
              <img
                alt="image"
                src="https://play.teleporthq.io/static/svg/default-img.svg"
                className="app-component-image11"
              />
              <span className="app-component-text22">Footer</span>
              <span className="app-component-text23">500+ items sold</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default AppComponent
