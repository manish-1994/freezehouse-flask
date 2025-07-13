particlesJS("particles-js", {
  particles: {
    number: {
      value: 30,
      density: {
        enable: true,
        value_area: 800
      }
    },
    shape: {
      type: "image",
      image: {
        src: "/static/img/snowflake.png", // path to your image
        width: 20,
        height: 20
      }
    },
    opacity: {
      value: 0.8,
      random: true
    },
    size: {
      value: 16,
      random: true
    },
    move: {
      enable: true,
      speed: 2,
      direction: "bottom",
      random: false,
      straight: false,
      out_mode: "out"
    },
    line_linked: {
      enable: false
    }
  },
  interactivity: {
    events: {
      onhover: {
        enable: false
      },
      onclick: {
        enable: false
      }
    }
  },
  retina_detect: true
});
