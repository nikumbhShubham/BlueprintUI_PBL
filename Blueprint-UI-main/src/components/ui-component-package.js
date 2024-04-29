import React from 'react'

import PropTypes from 'prop-types'

import './ui-component-package.css'

const UiComponentPackage = (props) => {
  return (
    <div className={`ui-component-package-container ${props.rootClassName} `}>
      <div className="ui-component-package-container1">
        <div className="ui-component-package-feature-card button">
          <img
            alt={props.imageAlt5}
            src={props.imageSrc4}
            className="ui-component-package-image"
          />
          <span className="ui-component-package-text">Footer</span>
          <span className="ui-component-package-text01">{props.text1141}</span>
        </div>
        <div className="ui-component-package-feature-card1 button">
          <img
            alt={props.imageAlt6}
            src={props.imageSrc5}
            className="ui-component-package-image1"
          />
          <span className="ui-component-package-text02">Form</span>
          <span className="ui-component-package-text03">{props.text114}</span>
        </div>
        <div className="ui-component-package-feature-card2 button">
          <img
            alt={props.imageAlt7}
            src={props.imageSrc6}
            className="ui-component-package-image2"
          />
          <span className="ui-component-package-text04">Header</span>
          <span className="ui-component-package-text05">{props.text1142}</span>
        </div>
      </div>
      <div className="ui-component-package-container2">
        <div className="ui-component-package-feature-card3 button">
          <img
            alt={props.imageAlt8}
            src={props.imageSrc7}
            className="ui-component-package-image3"
          />
          <span className="ui-component-package-text06">Footer</span>
          <span className="ui-component-package-text07">{props.text11411}</span>
        </div>
        <div className="ui-component-package-feature-card4 button">
          <img
            alt={props.imageAlt9}
            src={props.imageSrc8}
            className="ui-component-package-image4"
          />
          <span className="ui-component-package-text08">Form</span>
          <span className="ui-component-package-text09">{props.text1143}</span>
        </div>
        <div className="ui-component-package-feature-card5 button">
          <img
            alt={props.imageAlt10}
            src={props.imageSrc9}
            className="ui-component-package-image5"
          />
          <span className="ui-component-package-text10">Header</span>
          <span className="ui-component-package-text11">{props.text11421}</span>
        </div>
      </div>
    </div>
  )
}

UiComponentPackage.defaultProps = {
  text11111: '500+ items sold',
  imageAlt21: 'image',
  imageAlt3: 'image',
  text21: 'Form',
  imageAlt1: 'image',
  text1131: '500+ items sold',
  text2111: 'Form',
  text: 'Header',
  text212: 'Form',
  imageAlt32: 'image',
  text1111: '500+ items sold',
  imageSrc5: 'https://play.teleporthq.io/static/svg/default-img.svg',
  text22: 'Form',
  imageAlt4: 'image',
  imageSrc8: 'https://play.teleporthq.io/static/svg/default-img.svg',
  text241: 'Form',
  imageSrc9: 'https://play.teleporthq.io/static/svg/default-img.svg',
  imageSrc3: 'https://play.teleporthq.io/static/svg/default-img.svg',
  text211: 'Form',
  text113: '500+ items sold',
  imageAlt: 'image',
  text11421: '500+ items sold',
  imageSrc7: 'https://play.teleporthq.io/static/svg/default-img.svg',
  text1141: '500+ items sold',
  imageAlt31: 'image',
  imageSrc:
    'https://images.unsplash.com/photo-1554224154-22dec7ec8818?ixid=M3w5MTMyMXwwfDF8c2VhcmNofDE0fHxmb3JtfGVufDB8fHx8MTcxMjM4MTI0M3ww&ixlib=rb-4.0.3&w=200',
  imageAlt8: 'image',
  imageSrc6: 'https://play.teleporthq.io/static/svg/default-img.svg',
  text1112: '500+ items sold',
  text2: 'Form',
  text11411: '500+ items sold',
  text24: 'Form',
  text11: '500+ items sold',
  text3: 'Form',
  text231: 'Form',
  imageSrc1:
    'https://images.unsplash.com/photo-1554224154-22dec7ec8818?ixid=M3w5MTMyMXwwfDF8c2VhcmNofDE0fHxmb3JtfGVufDB8fHx8MTcxMjM4MTI0M3ww&ixlib=rb-4.0.3&w=200',
  text242: 'Form',
  text12: '500+ items sold',
  imageAlt5: 'image',
  text111: '500+ items sold',
  text112: '500+ items sold',
  text1143: '500+ items sold',
  text23: 'Header',
  text114: '500+ items sold',
  imageAlt9: 'image',
  imageSrc2:
    'https://images.unsplash.com/photo-1554224154-22dec7ec8818?ixid=M3w5MTMyMXwwfDF8c2VhcmNofDE0fHxmb3JtfGVufDB8fHx8MTcxMjM4MTI0M3ww&ixlib=rb-4.0.3&w=200',
  imageAlt7: 'image',
  rootClassName: '',
  text1142: '500+ items sold',
  imageSrc4: 'https://play.teleporthq.io/static/svg/default-img.svg',
  imageSrc21:
    'https://images.unsplash.com/photo-1554224154-22dec7ec8818?ixid=M3w5MTMyMXwwfDF8c2VhcmNofDE0fHxmb3JtfGVufDB8fHx8MTcxMjM4MTI0M3ww&ixlib=rb-4.0.3&w=200',
  imageAlt6: 'image',
  text1: '500+ items sold',
  imageAlt2: 'image',
  imageAlt10: 'image',
}

UiComponentPackage.propTypes = {
  text11111: PropTypes.string,
  imageAlt21: PropTypes.string,
  imageAlt3: PropTypes.string,
  text21: PropTypes.string,
  imageAlt1: PropTypes.string,
  text1131: PropTypes.string,
  text2111: PropTypes.string,
  text: PropTypes.string,
  text212: PropTypes.string,
  imageAlt32: PropTypes.string,
  text1111: PropTypes.string,
  imageSrc5: PropTypes.string,
  text22: PropTypes.string,
  imageAlt4: PropTypes.string,
  imageSrc8: PropTypes.string,
  text241: PropTypes.string,
  imageSrc9: PropTypes.string,
  imageSrc3: PropTypes.string,
  text211: PropTypes.string,
  text113: PropTypes.string,
  imageAlt: PropTypes.string,
  text11421: PropTypes.string,
  imageSrc7: PropTypes.string,
  text1141: PropTypes.string,
  imageAlt31: PropTypes.string,
  imageSrc: PropTypes.string,
  imageAlt8: PropTypes.string,
  imageSrc6: PropTypes.string,
  text1112: PropTypes.string,
  text2: PropTypes.string,
  text11411: PropTypes.string,
  text24: PropTypes.string,
  text11: PropTypes.string,
  text3: PropTypes.string,
  text231: PropTypes.string,
  imageSrc1: PropTypes.string,
  text242: PropTypes.string,
  text12: PropTypes.string,
  imageAlt5: PropTypes.string,
  text111: PropTypes.string,
  text112: PropTypes.string,
  text1143: PropTypes.string,
  text23: PropTypes.string,
  text114: PropTypes.string,
  imageAlt9: PropTypes.string,
  imageSrc2: PropTypes.string,
  imageAlt7: PropTypes.string,
  rootClassName: PropTypes.string,
  text1142: PropTypes.string,
  imageSrc4: PropTypes.string,
  imageSrc21: PropTypes.string,
  imageAlt6: PropTypes.string,
  text1: PropTypes.string,
  imageAlt2: PropTypes.string,
  imageAlt10: PropTypes.string,
}

export default UiComponentPackage
