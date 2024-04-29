import React from 'react'

import PropTypes from 'prop-types'

import './footer.css'

const Footer = (props) => {
  return (
    <div className={`footer-container13 ${props.rootClassName} `}>
      <span className="footer-text">
        <span className="">
          © 2024 BlueprintUI , Inc. • Privacy • Terms • Sitemap
        </span>
      </span>
      <div className="footer-group14">
        <img
          alt={props.logoinstagram1Alt}
          src={props.logoinstagram1Src}
          className="footer-logoinstagram1"
        />
        <img
          alt={props.dribbblelogo1Alt}
          src={props.dribbblelogo1Src}
          className="footer-dribbblelogo1"
        />
        <img
          alt={props.linkedInlogo1Alt}
          src={props.linkedInlogo1Src}
          className="footer-linked-inlogo1"
        />
        <img
          alt={props.envelopeopen1Alt}
          src={props.envelopeopen1Src}
          className="footer-envelopeopen1"
        />
      </div>
    </div>
  )
}

Footer.defaultProps = {
  envelopeopen1Alt: 'Envelopeopen11312',
  rootClassName: '',
  logoinstagram1Src: '/external/logoinstagram11311-tb1v.svg',
  logoinstagram1Alt: 'Logoinstagram11311',
  linkedInlogo1Alt: 'LinkedInlogo11312',
  dribbblelogo1Src: '/external/dribbblelogo11312-bleq.svg',
  envelopeopen1Src: '/external/envelopeopen11312-xoxp.svg',
  dribbblelogo1Alt: 'Dribbblelogo11312',
  linkedInlogo1Src: '/external/linkedinlogo11312-4k.svg',
}

Footer.propTypes = {
  envelopeopen1Alt: PropTypes.string,
  rootClassName: PropTypes.string,
  logoinstagram1Src: PropTypes.string,
  logoinstagram1Alt: PropTypes.string,
  linkedInlogo1Alt: PropTypes.string,
  dribbblelogo1Src: PropTypes.string,
  envelopeopen1Src: PropTypes.string,
  dribbblelogo1Alt: PropTypes.string,
  linkedInlogo1Src: PropTypes.string,
}

export default Footer
