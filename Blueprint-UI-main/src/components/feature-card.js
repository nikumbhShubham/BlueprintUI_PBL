import React from 'react'
import { Link } from 'react-router-dom'

import PropTypes from 'prop-types'

import './feature-card.css'

const FeatureCard = (props) => {
  return (
    <div className={`feature-card-feature-card ${props.rootClassName} `}>
      <h2 className="feature-card-text">{props.heading}</h2>
      <span className="feature-card-text1">{props.text}</span>
      <Link to="/my-project" className="feature-card-navlink button">
        <span className="feature-card-text2">
          <span className="">Create team</span>
          <br className=""></br>
        </span>
      </Link>
    </div>
  )
}

FeatureCard.defaultProps = {
  heading: 'Create a team',
  text: 'Join/create a team and collaborate on a project\n',
  rootClassName: '',
}

FeatureCard.propTypes = {
  heading: PropTypes.string,
  text: PropTypes.string,
  rootClassName: PropTypes.string,
}

export default FeatureCard
