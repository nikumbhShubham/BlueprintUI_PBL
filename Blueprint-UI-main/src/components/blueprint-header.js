import React from 'react'

import PropTypes from 'prop-types'

import './blueprint-header.css'

const BlueprintHeader = (props) => {
  return (
    <div className={`blueprint-header-container68 ${props.rootClassName} `}>
      <div className="blueprint-header-container71">
        <div className="blueprint-header-avatar9">
          <img
            alt={props.rectangleAlt}
            src={props.rectangleSrc}
            className="blueprint-header-rectangle"
          />
          <div className="blueprint-header-frame">
            <span className="blueprint-header-text">{props.text}</span>
          </div>
        </div>
        <span className="blueprint-header-text01">
          <span className="">View profile</span>
        </span>
        <div className="blueprint-header-sidebar-menu1">
          <div className="blueprint-header-frame1">
            <span className="blueprint-header-text03">
              <span className="">Analytics</span>
            </span>
          </div>
          <div className="blueprint-header-frame2">
            <img
              alt={props.rectangleAlt1}
              src={props.rectangleSrc1}
              className="blueprint-header-rectangle1"
            />
            <span className="blueprint-header-text05">
              <span className="">Dashboard</span>
            </span>
          </div>
          <div className="blueprint-header-frame3">
            <span className="blueprint-header-text07">
              <span className="">Projects</span>
            </span>
          </div>
          <div className="blueprint-header-frame4">
            <span className="blueprint-header-text09">
              <span className="">Integrations</span>
            </span>
          </div>
          <div className="blueprint-header-frame5">
            <span className="blueprint-header-text11">
              <span className="">Teams</span>
            </span>
          </div>
          <div className="blueprint-header-frame6">
            <span className="blueprint-header-text13">
              <span className="">Messages</span>
            </span>
          </div>
        </div>
        <span className="blueprint-header-text15">
          <span className="">Amanda</span>
        </span>
        <div className="blueprint-header-image75">
          <div className="blueprint-header-group">
            <div className="blueprint-header-group01">
              <div className="blueprint-header-group02">
                <div className="blueprint-header-group03">
                  <div className="blueprint-header-group04"></div>
                  <div className="blueprint-header-group05"></div>
                  <div className="blueprint-header-group06"></div>
                  <div className="blueprint-header-group07"></div>
                  <div className="blueprint-header-group08"></div>
                  <div className="blueprint-header-group09"></div>
                  <div className="blueprint-header-group10"></div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      <span className="blueprint-header-text17">
        <span className="">&lt;BlueprintUI&gt;</span>
      </span>
    </div>
  )
}

BlueprintHeader.defaultProps = {
  rectangleSrc: '/external/rectangle1344-s42p-200h.png',
  text: '',
  rectangleSrc1: '/external/rectangle1356-4ymj-200h.png',
  rootClassName: '',
  rectangleAlt: 'Rectangle1344',
  rectangleAlt1: 'Rectangle1356',
}

BlueprintHeader.propTypes = {
  rectangleSrc: PropTypes.string,
  text: PropTypes.string,
  rectangleSrc1: PropTypes.string,
  rootClassName: PropTypes.string,
  rectangleAlt: PropTypes.string,
  rectangleAlt1: PropTypes.string,
}

export default BlueprintHeader
