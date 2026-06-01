import { Component } from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';

import styled from 'styled-components';
import oc from 'open-color';

import { MODEL, fetchSubscriber, deleteSubscriber } from 'modules/crud/subscriber';
import { clearActionStatus } from 'modules/crud/actions';
import { select, selectActionStatus } from 'modules/crud/selectors';
import * as Notification from 'modules/notification/actions';

import {
  Layout,
  Subscriber,
  Spinner,
  FloatingButton,
  Blank,
  Dimmed,
  Confirm
} from 'components';

import Document from './Document';

const NotFound = styled.div`
  display: block;
  margin: 2rem auto;
  max-width: 700px;
  padding: 1rem;
  text-align: center;
  font-size: 1rem;
  color: ${oc.gray[6]};
`;

class Collection extends Component {
  state = {
    search: '',
    searchedImsi: null,
    document: {
      action: '',
      visible: false,
      dimmed: false
    },
    confirm: {
      visible: false,
      imsi: ''
    },
    view: {
      visible: false,
      disableOnClickOutside: false,
      imsi: ''
    }
  };

  componentWillReceiveProps(nextProps) {
    const { status } = nextProps;
    const { dispatch } = this.props;
    const { searchedImsi } = this.state;

    if (searchedImsi) {
      const subscriber = select(fetchSubscriber(searchedImsi), nextProps.crud);
      if (subscriber.needsFetch) {
        dispatch(fetchSubscriber(searchedImsi));
      }
    }

    if (status.response) {
      dispatch(Notification.success({
        title: 'Subscriber',
        message: `${status.id} has been deleted`
      }));
      dispatch(clearActionStatus(MODEL, 'delete'));

      if (status.id === searchedImsi) {
        this.setState({ search: '', searchedImsi: null });
      }
    }

    if (status.error) {
      const response = status.error.response || {};
      let title = 'Unknown Code';
      let message = 'Unknown Error';
      if (response.data && response.data.name && response.data.message) {
        title = response.data.name;
        message = response.data.message;
      } else {
        title = response.status;
        message = response.statusText;
      }

      dispatch(Notification.error({
        title,
        message,
        autoDismiss: 0,
        action: {
          label: 'Dismiss'
        }
      }));
      dispatch(clearActionStatus(MODEL, 'delete'));
    }
  }

  handleSearchChange = (e) => {
    this.setState({
      search: e.target.value
    });
  }

  handleSearchClear = () => {
    this.setState({
      search: '',
      searchedImsi: null
    });
  }

  handleSearchKeyDown = (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      this.handleSearch();
    }
  }

  handleSearch = () => {
    const imsi = this.state.search.trim();
    if (!imsi) {
      return;
    }

    this.setState({ searchedImsi: imsi });
    this.props.dispatch(fetchSubscriber(imsi));
  }

  documentHandler = {
    show: (action, payload) => {
      this.setState({
        document: {
          action,
          visible: true,
          dimmed: true,
          ...payload
        },
        view: {
          ...this.state.view,
          disableOnClickOutside: true
        }
      })
    },
    hide: () => {
      this.setState({
        document: {
          action: '',
          visible: false,
          dimmed: false
        },
        view: {
          ...this.state.view,
          disableOnClickOutside: false
        }
      })
    },
    actions: {
      create: () => {
        this.documentHandler.show('create');
      },
      update: (imsi) => {
        this.documentHandler.show('update', { imsi });
      }
    }
  }

  confirmHandler = {
    show: (imsi) => {
      this.setState({
        confirm: {
          visible: true,
          imsi,
        },
        view: {
          ...this.state.view,
          disableOnClickOutside: true
        }
      })
    },
    hide: () => {
      this.setState({
        confirm: {
          ...this.state.confirm,
          visible: false
        },
        view: {
          ...this.state.view,
          disableOnClickOutside: false
        }
      })
    },
    actions : {
      delete: () => {
        const { dispatch } = this.props

        if (this.state.confirm.visible === true) {
          this.confirmHandler.hide();
          this.documentHandler.hide();
          this.viewHandler.hide();

          dispatch(deleteSubscriber(this.state.confirm.imsi));
        }
      }
    }
  }

  viewHandler = {
    show: (imsi) => {
      this.setState({
        view: {
          imsi,
          visible: true,
          disableOnClickOutside: false
        }
      });
    },
    hide: () => {
      this.setState({
        view: {
          ...this.state.view,
          visible: false
        }
      })
    }
  }


  render() {
    const {
      handleSearchChange,
      handleSearchClear,
      handleSearchKeyDown,
      documentHandler,
      viewHandler,
      confirmHandler
    } = this;

    const {
      search,
      searchedImsi,
      document
    } = this.state;

    const {
      crud,
      status
    } = this.props

    const subscriber = searchedImsi
      ? select(fetchSubscriber(searchedImsi), crud)
      : { isLoading: false, needsFetch: false, data: null, error: null };

    const subscribers = subscriber.data ? [subscriber.data] : [];
    const isLoading = searchedImsi && subscriber.isLoading;
    const notFound = searchedImsi && !subscriber.isLoading && !subscriber.data;

    return (
      <Layout.Content>
        <Subscriber.Search
          onChange={handleSearchChange}
          value={search}
          onClear={handleSearchClear}
          onKeyDown={handleSearchKeyDown} />
        {subscribers.length > 0 &&
          <Subscriber.List
            subscribers={subscribers}
            deletedImsi={status.id}
            onView={viewHandler.show}
            onEdit={documentHandler.actions.update}
            onDelete={confirmHandler.show}
            search="" />}
        {isLoading && <Spinner md />}
        {notFound && (
          <NotFound>No subscriber found for IMSI {searchedImsi}</NotFound>
        )}
        <Blank
          visible={!isLoading && !searchedImsi}
          title="ADD A SUBSCRIBER"
          body="Enter an IMSI above to find a subscriber, or add a new one."
          onTitle={documentHandler.actions.create}
          />
        <FloatingButton onClick={documentHandler.actions.create}/>
        <Subscriber.View
          visible={this.state.view.visible}
          subscriber={subscriber.data}
          disableOnClickOutside={this.state.view.disableOnClickOutside}
          onEdit={documentHandler.actions.update}
          onDelete={confirmHandler.show}
          onHide={viewHandler.hide}/>
        <Document
          { ...document }
          onEdit={documentHandler.actions.update}
          onDelete={confirmHandler.show}
          onHide={documentHandler.hide} />
        <Dimmed visible={document.dimmed} />
        <Confirm
          visible={this.state.confirm.visible}
          message="Delete this subscriber?"
          onOutside={confirmHandler.hide}
          buttons={[
            { text: "CANCEL", action: confirmHandler.hide, info:true },
            { text: "DELETE", action: confirmHandler.actions.delete, danger:true }
          ]}/>
      </Layout.Content>
    )
  }
}

Collection = connect(
  (state) => ({
    crud: state.crud,
    status: selectActionStatus(MODEL, state.crud, 'delete')
  })
)(Collection);

export default Collection;
