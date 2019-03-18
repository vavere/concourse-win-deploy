# concourse-win-deploy

[Concourse CI](https://concourse-ci.org/) resource which install msi package in a remote window box.

Written in [python](https://www.python.org/) as part of my *concourse* learning exercises.

Similary structured as other *concourse*  resource [concourse-smb-share](https://github.com/vavere/concourse-smb-share) wich was intentionaly written in javascript as [node.js](https://nodejs.org/en/) project. Now i can compare.

## Why?

Yes it's serious question. Why involve more than 10 years old windows deployment technologies in pretty modern devops continuous integration pipeline? 

Firstly, it is possible and secondly, at least for me, they are some kind of deep diving courses in [CI](https://en.wikipedia.org/wiki/Continuous_integration) world.

And why not a [Jenkins](https://jenkins.io/)? Its plugins support everything in the world. It's personal, I don't like [java](https://www.java.com/en/) projects at all, ups ...

## How to use

First of all, i pipeline define [resource type](https://concourse-ci.org/resource-types.html):

```yaml
- name: win-deploy
  type: docker-image
  source:
    repository: vavere/concourse-win-deploy
```

Second configure [resource](https://concourse-ci.org/resources.html):

```yaml
- name: win-server
  type: win-deploy
  source:
    host: bigone
    user: ((admin_name))
    pass: ((admin_pass))
```

And as posibly last step in pipeline [jobs](https://concourse-ci.org/jobs.html) deploy your product:

```yaml
- put: win-server
  params:
    file: result/product.msi
```

## Tests

Sorry, I'm still learning *python*.

## License

The MIT License (MIT)
