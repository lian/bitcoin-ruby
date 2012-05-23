<?xml version="1.0" encoding="UTF-8"?>
<interface>
  <!-- interface-requires gtk+ 3.0 -->
  <object class="GtkAboutDialog" id="about_dialog">
    <property name="can_focus">False</property>
    <property name="border_width">5</property>
    <property name="title" translatable="yes">About</property>
    <property name="type_hint">dialog</property>
    <property name="program_name">Bitcoin-Ruby GUI</property>
    <property name="version">0.0.1</property>
    <property name="copyright" translatable="yes">Copyright (c) 2011 Julian Langschaedel &lt;meta.rb@gmail.com&gt;
Copyright (c) 2012 Marius Hanne &lt;marius.hanne@sourceagency.org&gt;</property>
    <property name="comments" translatable="yes">a ruby library for interacting with the bitcoin protocol/network</property>
    <property name="website">http://mhanne.github.com/bitcoin-ruby/</property>
    <property name="license" translatable="yes">Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.</property>
    <property name="authors">Julian Langschaedel
Marius Hanne</property>
    <property name="logo">bitcoin-ruby.png</property>
    <property name="wrap_license">True</property>
    <property name="license_type">artistic</property>
    <signal name="response" handler="on_about_close" swapped="no"/>
    <child internal-child="vbox">
      <object class="GtkBox" id="aboutdialog-vbox1">
        <property name="can_focus">False</property>
        <property name="orientation">vertical</property>
        <property name="spacing">2</property>
        <child internal-child="action_area">
          <object class="GtkButtonBox" id="aboutdialog-action_area1">
            <property name="can_focus">False</property>
            <property name="layout_style">end</property>
            <signal name="add" handler="on_about_close" swapped="no"/>
            <signal name="remove" handler="on_about_close" swapped="no"/>
          </object>
          <packing>
            <property name="expand">False</property>
            <property name="fill">True</property>
            <property name="pack_type">end</property>
            <property name="position">0</property>
          </packing>
        </child>
        <child>
          <placeholder/>
        </child>
      </object>
    </child>
  </object>
  <object class="GtkAccelGroup" id="accelgroup1">
    <signal name="accel-activate" handler="on_accel_activate" swapped="no"/>
  </object>
  <object class="GtkAction" id="action_exit">
    <property name="label" translatable="yes">aaa</property>
    <signal name="activate" handler="on_exit" swapped="no"/>
  </object>
  <object class="GtkTreeStore" id="addr_store">
    <columns>
      <!-- column-name Address -->
      <column type="gchararray"/>
      <!-- column-name column1 -->
      <column type="gchararray"/>
      <!-- column-name Balance -->
      <column type="gchararray"/>
    </columns>
  </object>
  <object class="GtkImage" id="image_new_addr">
    <property name="visible">True</property>
    <property name="can_focus">False</property>
    <property name="stock">gtk-add</property>
  </object>
  <object class="GtkImage" id="image_new_tx">
    <property name="visible">True</property>
    <property name="can_focus">False</property>
    <property name="stock">gtk-go-forward</property>
  </object>
  <object class="GtkListStore" id="liststore1"/>
  <object class="GtkWindow" id="main_window">
    <property name="can_focus">False</property>
    <property name="title" translatable="yes">Bitcoin-Ruby GUI</property>
    <accel-groups>
      <group name="accelgroup1"/>
    </accel-groups>
    <signal name="delete-event" handler="on_exit" swapped="no"/>
    <child>
      <object class="GtkBox" id="box1">
        <property name="visible">True</property>
        <property name="can_focus">False</property>
        <property name="orientation">vertical</property>
        <child>
          <object class="GtkMenuBar" id="menubar1">
            <property name="visible">True</property>
            <property name="can_focus">False</property>
            <child>
              <object class="GtkMenuItem" id="menuitem1">
                <property name="use_action_appearance">False</property>
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="label" translatable="yes">_File</property>
                <property name="use_underline">True</property>
                <child type="submenu">
                  <object class="GtkMenu" id="menu1">
                    <property name="visible">True</property>
                    <property name="can_focus">False</property>
                    <child>
                      <object class="GtkImageMenuItem" id="menu_file_new">
                        <property name="label">gtk-new</property>
                        <property name="use_action_appearance">False</property>
                        <property name="visible">True</property>
                        <property name="can_focus">False</property>
                        <property name="use_underline">True</property>
                        <property name="use_stock">True</property>
                        <signal name="activate" handler="on_new_wallet" swapped="no"/>
                      </object>
                    </child>
                    <child>
                      <object class="GtkImageMenuItem" id="menu_file_open">
                        <property name="label">gtk-open</property>
                        <property name="use_action_appearance">False</property>
                        <property name="visible">True</property>
                        <property name="can_focus">False</property>
                        <property name="use_underline">True</property>
                        <property name="use_stock">True</property>
                        <signal name="activate" handler="on_open_wallet" swapped="no"/>
                      </object>
                    </child>
                    <child>
                      <object class="GtkSeparatorMenuItem" id="separatormenuitem1">
                        <property name="use_action_appearance">False</property>
                        <property name="visible">True</property>
                        <property name="can_focus">False</property>
                      </object>
                    </child>
                    <child>
                      <object class="GtkImageMenuItem" id="menu_file_quit">
                        <property name="label">gtk-quit</property>
                        <property name="use_action_appearance">False</property>
                        <property name="related_action">action_exit</property>
                        <property name="visible">True</property>
                        <property name="can_focus">False</property>
                        <property name="use_underline">True</property>
                        <property name="use_stock">True</property>
                        <signal name="activate" handler="on_exit" swapped="no"/>
                      </object>
                    </child>
                  </object>
                </child>
              </object>
            </child>
            <child>
              <object class="GtkMenuItem" id="menuitem2">
                <property name="use_action_appearance">False</property>
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="label" translatable="yes">_Edit</property>
                <property name="use_underline">True</property>
                <child type="submenu">
                  <object class="GtkMenu" id="menu2">
                    <property name="visible">True</property>
                    <property name="can_focus">False</property>
                    <child>
                      <object class="GtkImageMenuItem" id="menu_edit_copy">
                        <property name="label">gtk-copy</property>
                        <property name="use_action_appearance">False</property>
                        <property name="visible">True</property>
                        <property name="can_focus">False</property>
                        <property name="use_underline">True</property>
                        <property name="use_stock">True</property>
                        <signal name="activate" handler="on_copy_addr" swapped="no"/>
                      </object>
                    </child>
                    <child>
                      <object class="GtkImageMenuItem" id="menu_edit_paste">
                        <property name="label">gtk-paste</property>
                        <property name="use_action_appearance">False</property>
                        <property name="visible">True</property>
                        <property name="can_focus">False</property>
                        <property name="use_underline">True</property>
                        <property name="use_stock">True</property>
                        <signal name="activate" handler="on_paste_addr" swapped="no"/>
                      </object>
                    </child>
                    <child>
                      <object class="GtkSeparatorMenuItem" id="separatormenuitem2">
                        <property name="use_action_appearance">False</property>
                        <property name="visible">True</property>
                        <property name="can_focus">False</property>
                      </object>
                    </child>
                    <child>
                      <object class="GtkImageMenuItem" id="menu_edit_preferences">
                        <property name="label">gtk-preferences</property>
                        <property name="use_action_appearance">False</property>
                        <property name="visible">True</property>
                        <property name="can_focus">False</property>
                        <property name="use_underline">True</property>
                        <property name="use_stock">True</property>
                        <signal name="activate" handler="on_preferences" swapped="no"/>
                      </object>
                    </child>
                  </object>
                </child>
              </object>
            </child>
            <child>
              <object class="GtkMenuItem" id="menuitem3">
                <property name="use_action_appearance">False</property>
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="label" translatable="yes">_View</property>
                <property name="use_underline">True</property>
                <child type="submenu">
                  <object class="GtkMenu" id="menu4">
                    <property name="visible">True</property>
                    <property name="can_focus">False</property>
                    <child>
                      <object class="GtkCheckMenuItem" id="check_unconfirmed">
                        <property name="use_action_appearance">False</property>
                        <property name="visible">True</property>
                        <property name="can_focus">False</property>
                        <property name="tooltip_text" translatable="yes">Display transactions that are not yet confirmed and use unconfirmed values to calculate balances</property>
                        <property name="label" translatable="yes">Display Unconfirmed</property>
                        <property name="use_underline">True</property>
                        <signal name="toggled" handler="on_check_unconfirmed_toggled" swapped="no"/>
                      </object>
                    </child>
                  </object>
                </child>
              </object>
            </child>
            <child>
              <object class="GtkMenuItem" id="menuitem4">
                <property name="use_action_appearance">False</property>
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="label" translatable="yes">_Help</property>
                <property name="use_underline">True</property>
                <child type="submenu">
                  <object class="GtkMenu" id="menu3">
                    <property name="visible">True</property>
                    <property name="can_focus">False</property>
                    <child>
                      <object class="GtkImageMenuItem" id="menu_help_about">
                        <property name="label">gtk-about</property>
                        <property name="use_action_appearance">False</property>
                        <property name="visible">True</property>
                        <property name="can_focus">False</property>
                        <property name="use_underline">True</property>
                        <property name="use_stock">True</property>
                        <property name="accel_group">accelgroup1</property>
                        <signal name="activate" handler="on_about" swapped="no"/>
                      </object>
                    </child>
                  </object>
                </child>
              </object>
            </child>
          </object>
          <packing>
            <property name="expand">False</property>
            <property name="fill">True</property>
            <property name="position">0</property>
          </packing>
        </child>
        <child>
          <object class="GtkNotebook" id="notebook">
            <property name="visible">True</property>
            <property name="can_focus">True</property>
            <child>
              <object class="GtkScrolledWindow" id="scrolledwindow1">
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="shadow_type">in</property>
                <child>
                  <object class="GtkTreeView" id="addr_view">
                    <property name="visible">True</property>
                    <property name="can_focus">True</property>
                    <property name="model">addr_store</property>
                    <property name="enable_grid_lines">both</property>
                    <child internal-child="selection">
                      <object class="GtkTreeSelection" id="treeview-selection1"/>
                    </child>
                  </object>
                </child>
              </object>
              <packing>
                <property name="tab_expand">True</property>
              </packing>
            </child>
            <child type="tab">
              <object class="GtkLabel" id="notebook_label_addresses">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="label" translatable="yes">Addresses</property>
              </object>
              <packing>
                <property name="tab_fill">False</property>
              </packing>
            </child>
            <child>
              <object class="GtkScrolledWindow" id="scrolledwindow2">
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="shadow_type">in</property>
                <child>
                  <object class="GtkTreeView" id="tx_view">
                    <property name="visible">True</property>
                    <property name="can_focus">True</property>
                    <child internal-child="selection">
                      <object class="GtkTreeSelection" id="treeview-selection2"/>
                    </child>
                  </object>
                </child>
              </object>
              <packing>
                <property name="position">1</property>
                <property name="tab_expand">True</property>
              </packing>
            </child>
            <child type="tab">
              <object class="GtkLabel" id="notebook_label_transactions">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="label" translatable="yes">Transactions</property>
              </object>
              <packing>
                <property name="position">1</property>
                <property name="tab_fill">False</property>
              </packing>
            </child>
            <child>
              <object class="GtkScrolledWindow" id="scrolledwindow3">
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="shadow_type">in</property>
                <child>
                  <object class="GtkTreeView" id="conn_view">
                    <property name="visible">True</property>
                    <property name="can_focus">True</property>
                    <child internal-child="selection">
                      <object class="GtkTreeSelection" id="treeview-selection4"/>
                    </child>
                  </object>
                </child>
              </object>
              <packing>
                <property name="position">2</property>
                <property name="tab_expand">True</property>
              </packing>
            </child>
            <child type="tab">
              <object class="GtkLabel" id="notebook_label_peers">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="label" translatable="yes">Connections</property>
              </object>
              <packing>
                <property name="position">2</property>
                <property name="tab_fill">False</property>
              </packing>
            </child>
            <child>
              <placeholder/>
            </child>
            <child type="tab">
              <placeholder/>
            </child>
          </object>
          <packing>
            <property name="expand">True</property>
            <property name="fill">True</property>
            <property name="position">1</property>
          </packing>
        </child>
        <child>
          <object class="GtkButtonBox" id="buttonbar">
            <property name="visible">True</property>
            <property name="can_focus">False</property>
            <property name="homogeneous">True</property>
            <property name="layout_style">start</property>
            <child>
              <object class="GtkButton" id="button_new_addr">
                <property name="label" translatable="yes">New Address</property>
                <property name="use_action_appearance">False</property>
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="receives_default">True</property>
                <property name="use_action_appearance">False</property>
                <property name="image">image_new_addr</property>
                <signal name="clicked" handler="on_new_addr" swapped="no"/>
              </object>
              <packing>
                <property name="expand">False</property>
                <property name="fill">True</property>
                <property name="position">0</property>
              </packing>
            </child>
            <child>
              <object class="GtkButton" id="button_new_tx">
                <property name="label" translatable="yes">New Transaction</property>
                <property name="use_action_appearance">False</property>
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="receives_default">True</property>
                <property name="use_action_appearance">False</property>
                <property name="image">image_new_tx</property>
                <signal name="clicked" handler="on_new_tx" swapped="no"/>
              </object>
              <packing>
                <property name="expand">False</property>
                <property name="fill">True</property>
                <property name="position">1</property>
              </packing>
            </child>
            <child>
              <placeholder/>
            </child>
          </object>
          <packing>
            <property name="expand">False</property>
            <property name="fill">True</property>
            <property name="position">2</property>
          </packing>
        </child>
        <child>
          <object class="GtkBox" id="box4">
            <property name="visible">True</property>
            <property name="can_focus">False</property>
            <child>
              <object class="GtkImage" id="image1">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="stock">gtk-network</property>
              </object>
              <packing>
                <property name="expand">False</property>
                <property name="fill">True</property>
                <property name="position">0</property>
              </packing>
            </child>
            <child>
              <object class="GtkStatusbar" id="status_network">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="orientation">vertical</property>
                <property name="spacing">2</property>
              </object>
              <packing>
                <property name="expand">True</property>
                <property name="fill">True</property>
                <property name="padding">10</property>
                <property name="position">1</property>
              </packing>
            </child>
            <child>
              <object class="GtkImage" id="image2">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="stock">gtk-harddisk</property>
              </object>
              <packing>
                <property name="expand">False</property>
                <property name="fill">True</property>
                <property name="position">2</property>
              </packing>
            </child>
            <child>
              <object class="GtkStatusbar" id="status_store">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="orientation">vertical</property>
                <property name="spacing">2</property>
              </object>
              <packing>
                <property name="expand">True</property>
                <property name="fill">True</property>
                <property name="padding">10</property>
                <property name="position">3</property>
              </packing>
            </child>
            <child>
              <object class="GtkImage" id="image3">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="stock">gtk-dialog-authentication</property>
              </object>
              <packing>
                <property name="expand">False</property>
                <property name="fill">True</property>
                <property name="position">4</property>
              </packing>
            </child>
            <child>
              <object class="GtkStatusbar" id="status_wallet">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="orientation">vertical</property>
                <property name="spacing">2</property>
              </object>
              <packing>
                <property name="expand">True</property>
                <property name="fill">True</property>
                <property name="padding">10</property>
                <property name="position">5</property>
              </packing>
            </child>
          </object>
          <packing>
            <property name="expand">False</property>
            <property name="fill">True</property>
            <property name="position">3</property>
          </packing>
        </child>
      </object>
    </child>
  </object>
  <object class="GtkMessageDialog" id="message_dialog">
    <property name="can_focus">False</property>
    <property name="border_width">5</property>
    <property name="window_position">mouse</property>
    <property name="type_hint">dialog</property>
    <property name="skip_taskbar_hint">True</property>
    <property name="text" translatable="yes">aaa</property>
    <property name="secondary_text" translatable="yes">aaaaa</property>
    <child internal-child="vbox">
      <object class="GtkBox" id="messagedialog-vbox1">
        <property name="can_focus">False</property>
        <property name="orientation">vertical</property>
        <property name="spacing">2</property>
        <child internal-child="action_area">
          <object class="GtkButtonBox" id="messagedialog-action_area1">
            <property name="can_focus">False</property>
            <property name="layout_style">end</property>
            <child>
              <object class="GtkButton" id="message_dialog_button_no">
                <property name="label">gtk-no</property>
                <property name="use_action_appearance">False</property>
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="receives_default">True</property>
                <property name="use_action_appearance">False</property>
                <property name="use_stock">True</property>
              </object>
              <packing>
                <property name="expand">False</property>
                <property name="fill">True</property>
                <property name="position">0</property>
              </packing>
            </child>
            <child>
              <object class="GtkButton" id="message_dialog_button_yes">
                <property name="label">gtk-yes</property>
                <property name="use_action_appearance">False</property>
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="receives_default">True</property>
                <property name="use_action_appearance">False</property>
                <property name="use_stock">True</property>
              </object>
              <packing>
                <property name="expand">False</property>
                <property name="fill">True</property>
                <property name="position">1</property>
              </packing>
            </child>
            <child>
              <object class="GtkButton" id="message_dialog_button_ok">
                <property name="label">gtk-ok</property>
                <property name="use_action_appearance">False</property>
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="receives_default">True</property>
                <property name="use_action_appearance">False</property>
                <property name="use_stock">True</property>
              </object>
              <packing>
                <property name="expand">False</property>
                <property name="fill">True</property>
                <property name="position">2</property>
              </packing>
            </child>
          </object>
          <packing>
            <property name="expand">False</property>
            <property name="fill">True</property>
            <property name="pack_type">end</property>
            <property name="position">0</property>
          </packing>
        </child>
      </object>
    </child>
    <action-widgets>
      <action-widget response="-1">message_dialog_button_no</action-widget>
      <action-widget response="1">message_dialog_button_yes</action-widget>
      <action-widget response="1">message_dialog_button_ok</action-widget>
    </action-widgets>
  </object>
  <object class="GtkDialog" id="new_addr_dialog">
    <property name="can_focus">False</property>
    <property name="border_width">5</property>
    <property name="title" translatable="yes">New Address</property>
    <property name="type_hint">dialog</property>
    <child internal-child="vbox">
      <object class="GtkBox" id="dialog-vbox1">
        <property name="can_focus">False</property>
        <property name="orientation">vertical</property>
        <property name="spacing">2</property>
        <child internal-child="action_area">
          <object class="GtkButtonBox" id="dialog-action_area1">
            <property name="can_focus">False</property>
            <property name="layout_style">end</property>
            <child>
              <object class="GtkButton" id="new_addr_dialog_cancel">
                <property name="label">gtk-cancel</property>
                <property name="use_action_appearance">False</property>
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="receives_default">True</property>
                <property name="use_action_appearance">False</property>
                <property name="use_stock">True</property>
                <signal name="clicked" handler="on_new_addr_cancel" swapped="no"/>
              </object>
              <packing>
                <property name="expand">False</property>
                <property name="fill">True</property>
                <property name="position">0</property>
              </packing>
            </child>
            <child>
              <object class="GtkButton" id="new_addr_dialog_apply">
                <property name="label">gtk-apply</property>
                <property name="use_action_appearance">False</property>
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="receives_default">True</property>
                <property name="use_action_appearance">False</property>
                <property name="use_stock">True</property>
                <signal name="clicked" handler="on_new_addr_apply" swapped="no"/>
              </object>
              <packing>
                <property name="expand">False</property>
                <property name="fill">True</property>
                <property name="position">1</property>
              </packing>
            </child>
          </object>
          <packing>
            <property name="expand">False</property>
            <property name="fill">True</property>
            <property name="pack_type">end</property>
            <property name="position">0</property>
          </packing>
        </child>
        <child>
          <object class="GtkGrid" id="grid8">
            <property name="visible">True</property>
            <property name="can_focus">False</property>
            <child>
              <object class="GtkLabel" id="label22">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="label" translatable="yes">Label</property>
              </object>
              <packing>
                <property name="left_attach">0</property>
                <property name="top_attach">0</property>
                <property name="width">1</property>
                <property name="height">1</property>
              </packing>
            </child>
            <child>
              <object class="GtkEntry" id="new_addr_entry_label">
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="invisible_char">●</property>
                <property name="invisible_char_set">True</property>
              </object>
              <packing>
                <property name="left_attach">1</property>
                <property name="top_attach">0</property>
                <property name="width">1</property>
                <property name="height">1</property>
              </packing>
            </child>
            <child>
              <object class="GtkCheckButton" id="new_addr_check_addr">
                <property name="label" translatable="yes">Address</property>
                <property name="use_action_appearance">False</property>
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="receives_default">False</property>
                <property name="use_action_appearance">False</property>
                <property name="xalign">0</property>
                <property name="draw_indicator">True</property>
              </object>
              <packing>
                <property name="left_attach">0</property>
                <property name="top_attach">1</property>
                <property name="width">1</property>
                <property name="height">1</property>
              </packing>
            </child>
            <child>
              <object class="GtkEntry" id="new_addr_entry_addr">
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="invisible_char">●</property>
                <property name="invisible_char_set">True</property>
              </object>
              <packing>
                <property name="left_attach">1</property>
                <property name="top_attach">1</property>
                <property name="width">1</property>
                <property name="height">1</property>
              </packing>
            </child>
            <child>
              <object class="GtkCheckButton" id="new_addr_check_pubkey">
                <property name="label" translatable="yes">Pubkey</property>
                <property name="use_action_appearance">False</property>
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="receives_default">False</property>
                <property name="use_action_appearance">False</property>
                <property name="xalign">0</property>
                <property name="draw_indicator">True</property>
              </object>
              <packing>
                <property name="left_attach">0</property>
                <property name="top_attach">2</property>
                <property name="width">1</property>
                <property name="height">1</property>
              </packing>
            </child>
            <child>
              <object class="GtkEntry" id="new_addr_entry_pubkey">
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="invisible_char">●</property>
                <property name="invisible_char_set">True</property>
              </object>
              <packing>
                <property name="left_attach">1</property>
                <property name="top_attach">2</property>
                <property name="width">1</property>
                <property name="height">1</property>
              </packing>
            </child>
            <child>
              <object class="GtkCheckButton" id="new_addr_check_mine">
                <property name="label" translatable="yes">Mine</property>
                <property name="use_action_appearance">False</property>
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="receives_default">False</property>
                <property name="use_action_appearance">False</property>
                <property name="xalign">0</property>
                <property name="active">True</property>
                <property name="draw_indicator">True</property>
              </object>
              <packing>
                <property name="left_attach">0</property>
                <property name="top_attach">3</property>
                <property name="width">1</property>
                <property name="height">1</property>
              </packing>
            </child>
            <child>
              <placeholder/>
            </child>
          </object>
          <packing>
            <property name="expand">False</property>
            <property name="fill">True</property>
            <property name="position">1</property>
          </packing>
        </child>
      </object>
    </child>
    <action-widgets>
      <action-widget response="0">new_addr_dialog_cancel</action-widget>
      <action-widget response="1">new_addr_dialog_apply</action-widget>
    </action-widgets>
  </object>
  <object class="GtkDialog" id="new_tx_dialog">
    <property name="can_focus">False</property>
    <property name="border_width">5</property>
    <property name="title" translatable="yes">New Transaction</property>
    <property name="type_hint">dialog</property>
    <child internal-child="vbox">
      <object class="GtkBox" id="dialog-vbox3">
        <property name="can_focus">False</property>
        <property name="orientation">vertical</property>
        <property name="spacing">2</property>
        <child internal-child="action_area">
          <object class="GtkButtonBox" id="dialog-action_area3">
            <property name="can_focus">False</property>
            <property name="layout_style">end</property>
            <child>
              <object class="GtkButton" id="button5">
                <property name="label">gtk-cancel</property>
                <property name="use_action_appearance">False</property>
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="receives_default">True</property>
                <property name="use_action_appearance">False</property>
                <property name="use_stock">True</property>
              </object>
              <packing>
                <property name="expand">False</property>
                <property name="fill">True</property>
                <property name="position">0</property>
              </packing>
            </child>
            <child>
              <object class="GtkButton" id="button6">
                <property name="label">gtk-apply</property>
                <property name="use_action_appearance">False</property>
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="receives_default">True</property>
                <property name="use_action_appearance">False</property>
                <property name="use_stock">True</property>
              </object>
              <packing>
                <property name="expand">False</property>
                <property name="fill">True</property>
                <property name="position">1</property>
              </packing>
            </child>
          </object>
          <packing>
            <property name="expand">False</property>
            <property name="fill">True</property>
            <property name="pack_type">end</property>
            <property name="position">0</property>
          </packing>
        </child>
        <child>
          <object class="GtkGrid" id="grid2">
            <property name="visible">True</property>
            <property name="can_focus">False</property>
            <child>
              <object class="GtkLabel" id="label4">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="label" translatable="yes">Recipient</property>
              </object>
              <packing>
                <property name="left_attach">0</property>
                <property name="top_attach">0</property>
                <property name="width">1</property>
                <property name="height">1</property>
              </packing>
            </child>
            <child>
              <object class="GtkLabel" id="label5">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="label" translatable="yes">Amount</property>
              </object>
              <packing>
                <property name="left_attach">0</property>
                <property name="top_attach">1</property>
                <property name="width">1</property>
                <property name="height">1</property>
              </packing>
            </child>
            <child>
              <object class="GtkEntry" id="new_tx_entry_address">
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="invisible_char">●</property>
              </object>
              <packing>
                <property name="left_attach">1</property>
                <property name="top_attach">0</property>
                <property name="width">1</property>
                <property name="height">1</property>
              </packing>
            </child>
            <child>
              <object class="GtkEntry" id="new_tx_entry_amount">
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="invisible_char">●</property>
              </object>
              <packing>
                <property name="left_attach">1</property>
                <property name="top_attach">1</property>
                <property name="width">1</property>
                <property name="height">1</property>
              </packing>
            </child>
          </object>
          <packing>
            <property name="expand">False</property>
            <property name="fill">True</property>
            <property name="position">1</property>
          </packing>
        </child>
      </object>
    </child>
    <action-widgets>
      <action-widget response="0">button5</action-widget>
      <action-widget response="1">button6</action-widget>
    </action-widgets>
  </object>
  <object class="GtkEntryCompletion" id="new_tx_recipient_completion"/>
  <object class="GtkMenu" id="popup_menu">
    <property name="visible">True</property>
    <property name="can_focus">False</property>
    <child>
      <object class="GtkImageMenuItem" id="menu_popup_quit">
        <property name="label">gtk-quit</property>
        <property name="use_action_appearance">False</property>
        <property name="related_action">action_exit</property>
        <property name="visible">True</property>
        <property name="can_focus">False</property>
        <property name="use_underline">True</property>
        <property name="use_stock">True</property>
      </object>
    </child>
  </object>
  <object class="GtkDialog" id="preferences_dialog">
    <property name="can_focus">False</property>
    <property name="border_width">5</property>
    <property name="title" translatable="yes">Preferences</property>
    <property name="type_hint">dialog</property>
    <child internal-child="vbox">
      <object class="GtkBox" id="dialog-vbox4">
        <property name="can_focus">False</property>
        <property name="orientation">vertical</property>
        <property name="spacing">2</property>
        <child internal-child="action_area">
          <object class="GtkButtonBox" id="dialog-action_area4">
            <property name="can_focus">False</property>
            <property name="layout_style">end</property>
            <child>
              <object class="GtkButton" id="button7">
                <property name="label">gtk-cancel</property>
                <property name="use_action_appearance">False</property>
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="receives_default">True</property>
                <property name="use_action_appearance">False</property>
                <property name="use_stock">True</property>
              </object>
              <packing>
                <property name="expand">False</property>
                <property name="fill">True</property>
                <property name="position">0</property>
              </packing>
            </child>
            <child>
              <object class="GtkButton" id="button8">
                <property name="label">gtk-save</property>
                <property name="use_action_appearance">False</property>
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="receives_default">True</property>
                <property name="use_action_appearance">False</property>
                <property name="use_stock">True</property>
              </object>
              <packing>
                <property name="expand">False</property>
                <property name="fill">True</property>
                <property name="position">1</property>
              </packing>
            </child>
          </object>
          <packing>
            <property name="expand">False</property>
            <property name="fill">True</property>
            <property name="pack_type">end</property>
            <property name="position">0</property>
          </packing>
        </child>
        <child>
          <object class="GtkNotebook" id="notebook1">
            <property name="visible">True</property>
            <property name="can_focus">True</property>
            <property name="tab_pos">left</property>
            <child>
              <object class="GtkGrid" id="grid3">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <child>
                  <object class="GtkLabel" id="label9">
                    <property name="visible">True</property>
                    <property name="can_focus">False</property>
                    <property name="label" translatable="yes">Network</property>
                  </object>
                  <packing>
                    <property name="left_attach">0</property>
                    <property name="top_attach">0</property>
                    <property name="width">1</property>
                    <property name="height">1</property>
                  </packing>
                </child>
                <child>
                  <object class="GtkLabel" id="label10">
                    <property name="visible">True</property>
                    <property name="can_focus">False</property>
                    <property name="label" translatable="yes">Command Socket</property>
                  </object>
                  <packing>
                    <property name="left_attach">0</property>
                    <property name="top_attach">1</property>
                    <property name="width">1</property>
                    <property name="height">1</property>
                  </packing>
                </child>
                <child>
                  <object class="GtkLabel" id="label11">
                    <property name="visible">True</property>
                    <property name="can_focus">False</property>
                    <property name="label" translatable="yes">Listen Socket</property>
                  </object>
                  <packing>
                    <property name="left_attach">0</property>
                    <property name="top_attach">2</property>
                    <property name="width">1</property>
                    <property name="height">1</property>
                  </packing>
                </child>
                <child>
                  <object class="GtkEntry" id="preferences_entry_command">
                    <property name="visible">True</property>
                    <property name="can_focus">True</property>
                    <property name="invisible_char">●</property>
                  </object>
                  <packing>
                    <property name="left_attach">1</property>
                    <property name="top_attach">1</property>
                    <property name="width">1</property>
                    <property name="height">1</property>
                  </packing>
                </child>
                <child>
                  <object class="GtkEntry" id="preferences_entry_listen">
                    <property name="visible">True</property>
                    <property name="can_focus">True</property>
                    <property name="invisible_char">●</property>
                  </object>
                  <packing>
                    <property name="left_attach">1</property>
                    <property name="top_attach">2</property>
                    <property name="width">1</property>
                    <property name="height">1</property>
                  </packing>
                </child>
                <child>
                  <object class="GtkEntry" id="preferences_entry_network">
                    <property name="visible">True</property>
                    <property name="can_focus">True</property>
                    <property name="invisible_char">●</property>
                  </object>
                  <packing>
                    <property name="left_attach">1</property>
                    <property name="top_attach">0</property>
                    <property name="width">1</property>
                    <property name="height">1</property>
                  </packing>
                </child>
                <child>
                  <object class="GtkLabel" id="label17">
                    <property name="visible">True</property>
                    <property name="can_focus">False</property>
                    <property name="label" translatable="yes">Storage Backend</property>
                  </object>
                  <packing>
                    <property name="left_attach">0</property>
                    <property name="top_attach">3</property>
                    <property name="width">1</property>
                    <property name="height">1</property>
                  </packing>
                </child>
                <child>
                  <object class="GtkComboBox" id="combobox2">
                    <property name="visible">True</property>
                    <property name="can_focus">False</property>
                  </object>
                  <packing>
                    <property name="left_attach">1</property>
                    <property name="top_attach">3</property>
                    <property name="width">1</property>
                    <property name="height">1</property>
                  </packing>
                </child>
              </object>
            </child>
            <child type="tab">
              <object class="GtkLabel" id="label6">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="label" translatable="yes">General</property>
              </object>
              <packing>
                <property name="tab_fill">False</property>
              </packing>
            </child>
            <child>
              <object class="GtkGrid" id="grid4">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <child>
                  <object class="GtkLabel" id="label12">
                    <property name="visible">True</property>
                    <property name="can_focus">False</property>
                    <property name="label" translatable="yes">Headers Only</property>
                  </object>
                  <packing>
                    <property name="left_attach">0</property>
                    <property name="top_attach">0</property>
                    <property name="width">1</property>
                    <property name="height">1</property>
                  </packing>
                </child>
                <child>
                  <object class="GtkLabel" id="label13">
                    <property name="visible">True</property>
                    <property name="can_focus">False</property>
                    <property name="label" translatable="yes">DNS</property>
                  </object>
                  <packing>
                    <property name="left_attach">0</property>
                    <property name="top_attach">1</property>
                    <property name="width">1</property>
                    <property name="height">1</property>
                  </packing>
                </child>
                <child>
                  <object class="GtkLabel" id="label14">
                    <property name="visible">True</property>
                    <property name="can_focus">False</property>
                  </object>
                  <packing>
                    <property name="left_attach">0</property>
                    <property name="top_attach">2</property>
                    <property name="width">1</property>
                    <property name="height">1</property>
                  </packing>
                </child>
                <child>
                  <object class="GtkSwitch" id="switch1">
                    <property name="use_action_appearance">False</property>
                    <property name="visible">True</property>
                    <property name="can_focus">True</property>
                    <property name="use_action_appearance">False</property>
                  </object>
                  <packing>
                    <property name="left_attach">1</property>
                    <property name="top_attach">0</property>
                    <property name="width">1</property>
                    <property name="height">1</property>
                  </packing>
                </child>
                <child>
                  <object class="GtkSwitch" id="switch2">
                    <property name="use_action_appearance">False</property>
                    <property name="visible">True</property>
                    <property name="can_focus">True</property>
                    <property name="use_action_appearance">False</property>
                  </object>
                  <packing>
                    <property name="left_attach">1</property>
                    <property name="top_attach">1</property>
                    <property name="width">1</property>
                    <property name="height">1</property>
                  </packing>
                </child>
                <child>
                  <placeholder/>
                </child>
              </object>
              <packing>
                <property name="position">1</property>
              </packing>
            </child>
            <child type="tab">
              <object class="GtkLabel" id="label7">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="label" translatable="yes">Node</property>
              </object>
              <packing>
                <property name="position">1</property>
                <property name="tab_fill">False</property>
              </packing>
            </child>
            <child>
              <object class="GtkGrid" id="grid5">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <child>
                  <object class="GtkLabel" id="label15">
                    <property name="visible">True</property>
                    <property name="can_focus">False</property>
                    <property name="label" translatable="yes">Backend</property>
                  </object>
                  <packing>
                    <property name="left_attach">0</property>
                    <property name="top_attach">0</property>
                    <property name="width">1</property>
                    <property name="height">1</property>
                  </packing>
                </child>
                <child>
                  <object class="GtkLabel" id="label16">
                    <property name="visible">True</property>
                    <property name="can_focus">False</property>
                    <property name="label" translatable="yes">File</property>
                  </object>
                  <packing>
                    <property name="left_attach">1</property>
                    <property name="top_attach">0</property>
                    <property name="width">1</property>
                    <property name="height">1</property>
                  </packing>
                </child>
                <child>
                  <object class="GtkComboBox" id="combobox1">
                    <property name="visible">True</property>
                    <property name="can_focus">False</property>
                  </object>
                  <packing>
                    <property name="left_attach">0</property>
                    <property name="top_attach">1</property>
                    <property name="width">1</property>
                    <property name="height">1</property>
                  </packing>
                </child>
                <child>
                  <object class="GtkFileChooserButton" id="filechooserbutton1">
                    <property name="visible">True</property>
                    <property name="can_focus">False</property>
                    <property name="orientation">vertical</property>
                  </object>
                  <packing>
                    <property name="left_attach">1</property>
                    <property name="top_attach">1</property>
                    <property name="width">1</property>
                    <property name="height">1</property>
                  </packing>
                </child>
              </object>
              <packing>
                <property name="position">2</property>
              </packing>
            </child>
            <child type="tab">
              <object class="GtkLabel" id="label8">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="label" translatable="yes">Wallet</property>
              </object>
              <packing>
                <property name="position">2</property>
                <property name="tab_fill">False</property>
              </packing>
            </child>
          </object>
          <packing>
            <property name="expand">False</property>
            <property name="fill">True</property>
            <property name="position">1</property>
          </packing>
        </child>
      </object>
    </child>
    <action-widgets>
      <action-widget response="0">button7</action-widget>
      <action-widget response="0">button8</action-widget>
    </action-widgets>
  </object>
  <object class="GtkStatusIcon" id="statusicon">
    <property name="pixbuf">bitcoin-ruby.png</property>
  </object>
  <object class="GtkDialog" id="tx_dialog">
    <property name="can_focus">False</property>
    <property name="border_width">5</property>
    <property name="title" translatable="yes">Transaction</property>
    <property name="type_hint">dialog</property>
    <child internal-child="vbox">
      <object class="GtkBox" id="dialog-vbox6">
        <property name="can_focus">False</property>
        <property name="orientation">vertical</property>
        <property name="spacing">2</property>
        <child internal-child="action_area">
          <object class="GtkButtonBox" id="dialog-action_area6">
            <property name="can_focus">False</property>
            <property name="layout_style">end</property>
            <child>
              <placeholder/>
            </child>
            <child>
              <object class="GtkButton" id="button9">
                <property name="label">gtk-close</property>
                <property name="use_action_appearance">False</property>
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="receives_default">True</property>
                <property name="use_action_appearance">False</property>
                <property name="use_stock">True</property>
              </object>
              <packing>
                <property name="expand">False</property>
                <property name="fill">True</property>
                <property name="position">1</property>
              </packing>
            </child>
          </object>
          <packing>
            <property name="expand">False</property>
            <property name="fill">True</property>
            <property name="pack_type">end</property>
            <property name="position">0</property>
          </packing>
        </child>
        <child>
          <object class="GtkGrid" id="grid6">
            <property name="visible">True</property>
            <property name="can_focus">False</property>
            <child>
              <object class="GtkLabel" id="tx_label_hash">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="label" translatable="yes">label</property>
              </object>
              <packing>
                <property name="left_attach">0</property>
                <property name="top_attach">0</property>
                <property name="width">4</property>
                <property name="height">1</property>
              </packing>
            </child>
            <child>
              <object class="GtkScrolledWindow" id="scrolledwindow4">
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="shadow_type">in</property>
                <child>
                  <object class="GtkTreeView" id="treeview2">
                    <property name="visible">True</property>
                    <property name="can_focus">True</property>
                    <child internal-child="selection">
                      <object class="GtkTreeSelection" id="treeview-selection6"/>
                    </child>
                  </object>
                </child>
              </object>
              <packing>
                <property name="left_attach">2</property>
                <property name="top_attach">3</property>
                <property name="width">2</property>
                <property name="height">2</property>
              </packing>
            </child>
            <child>
              <object class="GtkScrolledWindow" id="scrolledwindow5">
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="shadow_type">in</property>
                <child>
                  <object class="GtkTreeView" id="tx_txin_view">
                    <property name="visible">True</property>
                    <property name="can_focus">True</property>
                    <child internal-child="selection">
                      <object class="GtkTreeSelection" id="treeview-selection5"/>
                    </child>
                  </object>
                </child>
              </object>
              <packing>
                <property name="left_attach">0</property>
                <property name="top_attach">3</property>
                <property name="width">2</property>
                <property name="height">2</property>
              </packing>
            </child>
            <child>
              <object class="GtkLabel" id="label19">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="label" translatable="yes">Value:</property>
              </object>
              <packing>
                <property name="left_attach">0</property>
                <property name="top_attach">1</property>
                <property name="width">1</property>
                <property name="height">1</property>
              </packing>
            </child>
            <child>
              <object class="GtkLabel" id="tx_label_value">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
              </object>
              <packing>
                <property name="left_attach">1</property>
                <property name="top_attach">1</property>
                <property name="width">1</property>
                <property name="height">1</property>
              </packing>
            </child>
            <child>
              <object class="GtkLabel" id="label21">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="label" translatable="yes">Confirmations:</property>
              </object>
              <packing>
                <property name="left_attach">2</property>
                <property name="top_attach">1</property>
                <property name="width">1</property>
                <property name="height">1</property>
              </packing>
            </child>
            <child>
              <object class="GtkLabel" id="tx_label_confirmations">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
              </object>
              <packing>
                <property name="left_attach">3</property>
                <property name="top_attach">1</property>
                <property name="width">1</property>
                <property name="height">1</property>
              </packing>
            </child>
            <child>
              <object class="GtkLabel" id="label18">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="label" translatable="yes">Inputs</property>
              </object>
              <packing>
                <property name="left_attach">0</property>
                <property name="top_attach">2</property>
                <property name="width">2</property>
                <property name="height">1</property>
              </packing>
            </child>
            <child>
              <object class="GtkLabel" id="label20">
                <property name="visible">True</property>
                <property name="can_focus">False</property>
                <property name="label" translatable="yes">Outputs</property>
              </object>
              <packing>
                <property name="left_attach">2</property>
                <property name="top_attach">2</property>
                <property name="width">2</property>
                <property name="height">1</property>
              </packing>
            </child>
          </object>
          <packing>
            <property name="expand">False</property>
            <property name="fill">True</property>
            <property name="position">1</property>
          </packing>
        </child>
      </object>
    </child>
    <action-widgets>
      <action-widget response="0">button9</action-widget>
    </action-widgets>
  </object>
  <object class="GtkWindow" id="tx_window">
    <property name="can_focus">False</property>
    <child>
      <placeholder/>
    </child>
  </object>
  <object class="GtkFileChooserDialog" id="wallet_open_dialog">
    <property name="can_focus">False</property>
    <property name="border_width">5</property>
    <property name="title" translatable="yes">Open wallet</property>
    <property name="window_position">center-on-parent</property>
    <property name="type_hint">dialog</property>
    <signal name="response" handler="on_foobar" swapped="no"/>
    <child internal-child="vbox">
      <object class="GtkBox" id="filechooserdialog-vbox1">
        <property name="can_focus">False</property>
        <property name="orientation">vertical</property>
        <property name="spacing">2</property>
        <child internal-child="action_area">
          <object class="GtkButtonBox" id="filechooserdialog-action_area1">
            <property name="can_focus">False</property>
            <property name="layout_style">end</property>
            <child>
              <object class="GtkButton" id="button1">
                <property name="label">gtk-cancel</property>
                <property name="use_action_appearance">False</property>
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="receives_default">True</property>
                <property name="use_action_appearance">False</property>
                <property name="use_stock">True</property>
                <signal name="clicked" handler="on_wallet_open_cancel" swapped="no"/>
              </object>
              <packing>
                <property name="expand">False</property>
                <property name="fill">True</property>
                <property name="position">0</property>
              </packing>
            </child>
            <child>
              <object class="GtkButton" id="button2">
                <property name="label">gtk-apply</property>
                <property name="use_action_appearance">False</property>
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="receives_default">True</property>
                <property name="use_action_appearance">False</property>
                <property name="use_stock">True</property>
                <signal name="clicked" handler="on_wallet_open" swapped="no"/>
              </object>
              <packing>
                <property name="expand">False</property>
                <property name="fill">True</property>
                <property name="position">1</property>
              </packing>
            </child>
          </object>
          <packing>
            <property name="expand">False</property>
            <property name="fill">True</property>
            <property name="pack_type">end</property>
            <property name="position">0</property>
          </packing>
        </child>
        <child>
          <object class="GtkLabel" id="label1">
            <property name="visible">True</property>
            <property name="can_focus">False</property>
            <property name="label" translatable="yes">Select a wallet file</property>
          </object>
          <packing>
            <property name="expand">False</property>
            <property name="fill">True</property>
            <property name="position">2</property>
          </packing>
        </child>
      </object>
    </child>
    <action-widgets>
      <action-widget response="0">button1</action-widget>
      <action-widget response="1">button2</action-widget>
    </action-widgets>
  </object>
  <object class="GtkFileChooserDialog" id="wallet_save_dialog">
    <property name="can_focus">False</property>
    <property name="border_width">5</property>
    <property name="title" translatable="yes">Save wallet</property>
    <property name="type_hint">dialog</property>
    <property name="action">save</property>
    <signal name="update-preview" handler="on_wallet_save_dialog_update_preview" swapped="no"/>
    <child internal-child="vbox">
      <object class="GtkBox" id="filechooserdialog-vbox2">
        <property name="can_focus">False</property>
        <property name="orientation">vertical</property>
        <property name="spacing">2</property>
        <child internal-child="action_area">
          <object class="GtkButtonBox" id="filechooserdialog-action_area2">
            <property name="can_focus">False</property>
            <property name="layout_style">end</property>
            <child>
              <object class="GtkButton" id="button3">
                <property name="label">gtk-cancel</property>
                <property name="use_action_appearance">False</property>
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="receives_default">True</property>
                <property name="use_action_appearance">False</property>
                <property name="use_stock">True</property>
                <signal name="clicked" handler="on_wallet_save_cancel" swapped="no"/>
              </object>
              <packing>
                <property name="expand">False</property>
                <property name="fill">True</property>
                <property name="position">0</property>
              </packing>
            </child>
            <child>
              <object class="GtkButton" id="button4">
                <property name="label">gtk-apply</property>
                <property name="use_action_appearance">False</property>
                <property name="visible">True</property>
                <property name="can_focus">True</property>
                <property name="receives_default">True</property>
                <property name="use_action_appearance">False</property>
                <property name="use_stock">True</property>
                <signal name="clicked" handler="on_wallet_save" swapped="no"/>
              </object>
              <packing>
                <property name="expand">False</property>
                <property name="fill">True</property>
                <property name="position">1</property>
              </packing>
            </child>
          </object>
          <packing>
            <property name="expand">False</property>
            <property name="fill">True</property>
            <property name="pack_type">end</property>
            <property name="position">0</property>
          </packing>
        </child>
        <child>
          <object class="GtkLabel" id="label3">
            <property name="visible">True</property>
            <property name="can_focus">False</property>
            <property name="label" translatable="yes">Choose a filename to save your wallet</property>
          </object>
          <packing>
            <property name="expand">False</property>
            <property name="fill">True</property>
            <property name="position">2</property>
          </packing>
        </child>
      </object>
    </child>
    <action-widgets>
      <action-widget response="0">button3</action-widget>
      <action-widget response="1">button4</action-widget>
    </action-widgets>
  </object>
</interface>
